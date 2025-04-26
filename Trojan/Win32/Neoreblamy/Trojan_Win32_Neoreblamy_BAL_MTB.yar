
rule Trojan_Win32_Neoreblamy_BAL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 48 fe 8b d6 e8 ?? ?? ff ff 03 c7 b9 c4 00 00 00 99 f7 f9 46 8b fa 83 fe 04 } //3
		$a_03_1 = {ff 03 04 b5 ?? ?? ?? ?? b9 c4 00 00 00 99 f7 f9 89 14 b5 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}