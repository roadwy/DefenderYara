
rule Trojan_Win32_Neoreblamy_CJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 4d f8 ff 34 8b ff 34 b7 e8 ?? ?? ff ff 89 04 b7 46 8b 45 } //5
		$a_01_1 = {8b 55 ec 59 59 8b 4d fc 89 04 8a 41 8b 45 f8 03 c7 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}