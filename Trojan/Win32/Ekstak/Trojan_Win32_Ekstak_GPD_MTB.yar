
rule Trojan_Win32_Ekstak_GPD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 b0 26 00 55 73 bd a6 } //4
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 b0 26 00 de ad c7 94 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4) >=4
 
}
rule Trojan_Win32_Ekstak_GPD_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 67 cb 7b 78 } //4
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 e6 8e a9 02 } //4
		$a_03_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 a8 fb 33 28 } //4
		$a_03_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 c4 0a 00 18 08 ca 51 } //4
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_03_2  & 1)*4+(#a_03_3  & 1)*4) >=4
 
}