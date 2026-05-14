
rule Trojan_Win32_Androm_BAL_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c2 83 c0 04 89 45 ec ff 75 fc b9 a6 5b 00 00 ff 75 f8 b9 a6 5b 00 00 ff 75 f0 b9 a6 5b 00 00 ff 75 f4 b9 a6 5b 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAL_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 03 c7 89 45 bc c7 45 ac b2 84 31 00 6a 00 e8 ?? ?? ?? ?? 8b 55 bc 03 55 ac 81 ea b2 84 31 00 2b d7 03 c2 50 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 13 83 c6 04 83 c3 04 3b 75 d4 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}