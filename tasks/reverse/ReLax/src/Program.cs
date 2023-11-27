
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using GEmojiSharp;
namespace Mark
{
    class Table
    {
        public Char[] alpha = new Char[11]
        {
            ":arrow_down:".GetEmoji().Raw[0],
            ":arrow_right:".GetEmoji().Raw[0], // normal subtitution
            ":arrow_forward:".GetEmoji().Raw[0], //end subtitution
            "❌"[0],
            ":zero:".GetEmoji().Raw[0],
            ":one:".GetEmoji().Raw[0],
            ":two:".GetEmoji().Raw[0],
            ":three:".GetEmoji().Raw[0],
            ":four:".GetEmoji().Raw[0],
            ":five:".GetEmoji().Raw[0],
            ":heavy_plus_sign:".GetEmoji().Raw[0],
        };
    }
    class Instruction
    {
        public string left;
        public string right;
        public int type;
        public Instruction(string l, string r, int t)
        {
            left = l;
            right = r;
            type = t;
        }
    }
    class Machine
    {
        private List<Instruction> instructions;
        public int index;
        public string buffer;
        public bool state;
        public bool Step()
        {
            Table tab = new Table();
            bool done = false;
            string r = tab.alpha[3] + buffer + tab.alpha[3];
            string replaced = r.Replace(instructions[index].left, instructions[index].right);
            replaced = Regex.Replace(replaced, "" + tab.alpha[3], "");
            if (replaced == buffer)
            {
                done = index == instructions.Count - 1 ? true : false;
                index += 1;
            }
            else
            {
                done = instructions[index].type == 1 ? true : false;
                buffer = replaced;
                index = 0;
            }
            state = !done;
            return state;
        }
        public string GetBuf()
        {
            return buffer;
        }
        private int COUNT(string source, char search)
        {
            int count = 0;
            foreach (char c in source)
                if (c == search) count++;
            return count;
        }
        public Machine(string data, string buf)
        {
            state = true;
            instructions = new List<Instruction>();
            index = 0;
            buffer = buf;
            if (buffer == null)
            {
                buffer = "";
            }
            string[] lines = data.Split(
                new string[] { "\r\n", "\r", "\n" },
                StringSplitOptions.None
            );
            for (int i = 0; i < lines.Length; i++)
            {
                lines[i] = string.Join(string.Empty, Regex.Matches(lines[i], Emoji.RegexPattern).Select(x => x.Value));
            }
            Table tab = new Table();
            List<String> prepared = new List<String>();
            foreach (string line in lines)
            {
                string prep = "";
                foreach (Char c in line)
                {
                    prep += Array.IndexOf(tab.alpha, c) > -1 ? c : "";
                }
                prepared.Add(prep);
            }
            foreach (string line in prepared)
            {
                string[] instrs = line.Split(
                    new string[] { "" + tab.alpha[1], "" + tab.alpha[2] },
                    StringSplitOptions.None
                    );
                if (COUNT(line, tab.alpha[1]) == 1)
                {
                    instructions.Add(new Instruction(instrs[0], instrs[1], 0));
                }
                else if (COUNT(line, tab.alpha[2]) == 1)
                {
                    instructions.Add(new Instruction(instrs[0], instrs[1], 1));
                }
            }
        }
    }

    internal class Executable
    {

        static void Main(string[] args)
        {
            string data;
            if (args.Length < 2)
            {
                Console.WriteLine("Usage ./mark.exe src.file input");
            }
            else if (!File.Exists(args[0]))
            {
                Console.WriteLine("Can't open file");
            }
            else
            {
                data = File.ReadAllText(args[0]);
                Machine machine = new Machine(data, args[1]);
                while (machine.Step()) ;
                Console.WriteLine("Output: " + machine.GetBuf());
            }

        }
    }
}
