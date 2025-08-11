
rule Trojan_Win32_Neoreblamy_CG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 23 45 0c 89 85 ?? ?? ff ff 8b 45 08 23 45 0c 89 85 } //2
		$a_01_1 = {2b c8 03 4d } //1
		$a_01_2 = {ff ff 2b 85 } //1
		$a_01_3 = {ff ff 89 85 } //1
		$a_01_4 = {ff ff 8b 85 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}