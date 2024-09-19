
rule Trojan_Win32_Smokeloader_SCMB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SCMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c7 c1 e0 04 03 45 d8 03 d7 33 c2 33 45 fc 2b f0 ff 4d ec 89 75 f0 0f 85 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}