
rule Trojan_Win32_Nildochi_STB{
	meta:
		description = "Trojan:Win32/Nildochi.STB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {5c 2e 5c 5c 57 69 6e 64 6f 5c 78 78 2e 46 4f 50 } //1 \.\\Windo\xx.FOP
		$a_01_1 = {25 73 5c 72 65 67 69 64 2e 31 39 39 31 2d 30 36 2e 63 6f 6d 2e 6d 69 63 72 6f 73 6f 66 74 2e 64 61 74 } //1 %s\regid.1991-06.com.microsoft.dat
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 73 2f 64 31 63 2e 64 61 74 } //1 http://%s/d1c.dat
		$a_01_3 = {2f 43 20 6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 44 49 53 41 42 4c 45 } //1 /C netsh firewall set opmode mode=DISABLE
		$a_01_4 = {70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 2e 00 64 00 6c 00 6c 00 } //1 payload.dll
		$a_01_5 = {62 00 6c 00 61 00 63 00 6b 00 73 00 69 00 67 00 6e 00 73 00 2e 00 74 00 78 00 74 00 } //1 blacksigns.txt
		$a_01_6 = {2e 70 68 70 3f 6e 3d 25 73 26 63 31 3d } //1 .php?n=%s&c1=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}