
rule Trojan_Win32_Derusbi_F_dha{
	meta:
		description = "Trojan:Win32/Derusbi.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 f9 1c 7c e2 33 c9 8a c1 b2 07 f6 ea 30 44 0d d8 41 83 f9 1c 7c f0 } //1
		$a_01_1 = {30 4c 05 84 40 83 f8 2e 72 f6 33 c0 30 4c 05 b4 40 83 f8 13 72 f6 } //1
		$a_01_2 = {5c 64 77 31 35 2e 65 78 65 } //1 \dw15.exe
		$a_01_3 = {25 25 54 45 4d 50 25 25 5c 25 73 5f 70 2e 61 78 } //1 %%TEMP%%\%s_p.ax
		$a_01_4 = {47 45 54 20 68 74 74 70 3a 2f 2f 00 25 5b 5e 3a 5d 3a 25 64 } //1 䕇⁔瑨灴⼺/嬥㩞㩝搥
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}