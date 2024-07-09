
rule Trojan_Win32_Thundershell_A{
	meta:
		description = "Trojan:Win32/Thundershell.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 14 e8 ?? ?? ?? ?? 83 fb 01 74 05 83 fb 02 75 05 e8 } //10
		$a_03_1 = {81 c1 01 10 00 00 89 94 24 1c 10 00 00 [0-08] c1 e9 02 f3 a5 85 d2 } //10
		$a_01_2 = {44 6c 6c 4d 61 69 6e 40 31 32 00 45 78 65 63 00 } //10 汄䵬楡䁮㈱䔀數c
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}