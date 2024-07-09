
rule Trojan_Win64_Thundershell_A{
	meta:
		description = "Trojan:Win64/Thundershell.A,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 ea 01 83 fa 01 77 05 e8 ?? ?? ?? ?? b8 01 00 00 00 48 83 c4 28 c3 } //10
		$a_03_1 = {41 b8 01 10 00 00 4c 8d 4c 24 20 4c 89 c9 e8 ?? ?? ?? ?? 49 89 c1 8b 05 ?? ?? ?? ?? 85 c0 74 08 } //10
		$a_01_2 = {44 6c 6c 4d 61 69 6e 00 45 78 65 63 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}