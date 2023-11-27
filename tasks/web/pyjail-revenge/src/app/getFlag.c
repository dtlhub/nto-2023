#include <unistd.h>

int main() {
  setreuid(geteuid(), getuid());
  system("cat /app/flag");
  return 0;
}
