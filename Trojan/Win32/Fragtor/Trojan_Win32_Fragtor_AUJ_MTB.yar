
rule Trojan_Win32_Fragtor_AUJ_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b 4d 08 c7 45 ec 01 00 00 00 c7 45 f0 f4 ab 48 00 89 4d f4 89 45 f8 8d 45 ec 66 c7 45 fc 01 00 50 e8 61 0e ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}