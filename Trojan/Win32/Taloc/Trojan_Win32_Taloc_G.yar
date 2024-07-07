
rule Trojan_Win32_Taloc_G{
	meta:
		description = "Trojan:Win32/Taloc.G,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 33 56 7a 5a 58 4a 7a 4c 6e 46 36 62 32 35 6c 4c 6e 46 78 4c 6d 4e 76 62 53 39 6d 59 32 63 74 59 6d 6c 75 4c 32 4e 6e 61 56 39 6e 5a 58 52 66 63 47 39 79 64 48 4a 68 61 58 51 75 5a 6d 4e 6e 50 33 56 70 62 6e 4d 39 } //1 aHR0cDovL3VzZXJzLnF6b25lLnFxLmNvbS9mY2ctYmluL2NnaV9nZXRfcG9ydHJhaXQuZmNnP3VpbnM9
		$a_01_1 = {61 48 52 30 63 44 6f 76 4c 7a 51 35 4c 6a 45 30 4d 79 34 79 4d 44 55 75 4d 6a 45 76 51 32 39 31 62 6e 51 75 59 58 4e 77 50 33 5a 6c 63 6a 30 77 4d 44 45 6d 62 57 46 6a 50 51 3d 3d } //1 aHR0cDovLzQ5LjE0My4yMDUuMjEvQ291bnQuYXNwP3Zlcj0wMDEmbWFjPQ==
		$a_01_2 = {55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 45 6c 75 64 47 56 79 62 6d 56 30 49 45 56 34 63 47 78 76 63 6d 56 79 58 45 31 68 61 57 35 63 55 33 52 68 63 6e 51 67 55 47 46 6e 5a 51 3d 3d } //1 U29mdHdhcmVcTWljcm9zb2Z0XEludGVybmV0IEV4cGxvcmVyXE1haW5cU3RhcnQgUGFnZQ==
		$a_01_3 = {64 33 64 33 4c 6d 35 68 64 6d 56 79 4c 6d 4e 76 62 51 3d 3d } //1 d3d3Lm5hdmVyLmNvbQ==
		$a_01_4 = {63 6d 56 6e 63 33 5a 79 4d 7a 49 67 4c 33 4d 67 65 6d 6c 77 5a 6d 78 6b 63 69 35 6b 62 47 77 3d } //1 cmVnc3ZyMzIgL3MgemlwZmxkci5kbGw=
		$a_01_5 = {58 45 46 77 63 45 52 68 64 47 46 63 54 47 39 6a 59 57 78 4d 62 33 64 63 } //1 XEFwcERhdGFcTG9jYWxMb3dc
		$a_01_6 = {4c 33 56 77 62 47 39 68 5a 43 35 77 61 48 41 3d } //1 L3VwbG9hZC5waHA=
		$a_01_7 = {73 79 73 74 6f 6d 00 61 77 65 6b 68 73 67 00 35 39 36 32 35 37 44 44 39 33 46 33 30 39 35 36 41 30 35 37 41 32 39 46 33 41 39 39 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}