# MyDH

_Author: [@y73n0k](https://github.com/y73n0k)_

> Недавно я узнал про протокол Диффи-Хеллмана, надеюсь я ничего не перепутал...

## Решение

Анализируем скрипт. Начинаем с функции `gen_params`. Условие цикла написано так, что возвращаемые значения $p, g$ имеют свойства:
* $\gcd(p, g) \neq 1$
* $g \le p$

Обозначим $G = \gcd(p, g)$

Так как нам даны $A, B$, то рассмотрим их

$A \equiv a \cdot g \pmod{p}$
<br>$B \equiv b \cdot g \pmod{p}$
<br>То есть
<br>$A = a \cdot g + k_A \cdot p$
<br>$B = b \cdot g + k_B \cdot p$

Для решения нам необходимо найти $S_A \equiv b \cdot A \equiv b \cdot a \cdot g \pmod{p}$

<br>Введём обозначения:
<br>$p_G = \frac{p}{G} \\ g_G = \frac{g}{G}$
<br>Разделим обе части на $G$:
<br>$A_G = \frac{A}{G} = \frac{a \cdot g + k_A \cdot p}{G} = a \cdot g_G + k_A \cdot p_G$
<br>$B_G = \frac{B}{G} = \frac{b \cdot g + k_B \cdot p}{G} = b \cdot g_G + k_B \cdot p_G$

Рассмотрим $A_G \cdot B_G \equiv a \cdot b \cdot g_G^2 \pmod{p_G}$
<br>Так как $\gcd(g_G, p_G) = 1$, то существует $g_G^{-1} \pmod{p_G}$
<br>Тогда: $A_G \cdot B_G \cdot g_G^{-1} \equiv a \cdot b \cdot g_G \pmod{p_G}$
<br>Домножим на $G$:
<br>$G \cdot A_G \cdot B_G \cdot g_G^{-1} \equiv G \cdot a \cdot b \cdot g_G \equiv a \cdot b \cdot g \equiv S_A \pmod{p_G}$

Получив $S_A$, восстанавливаем флаг.

[Решение](./writeup/solution.py)
