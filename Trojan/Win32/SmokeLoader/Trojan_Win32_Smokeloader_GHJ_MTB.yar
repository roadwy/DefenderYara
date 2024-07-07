
rule Trojan_Win32_Smokeloader_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c3 33 44 24 90 01 01 c7 05 90 01 08 2b f0 8b d6 c1 e2 90 01 01 89 44 24 90 01 01 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b c6 c1 e8 90 01 01 03 c5 81 3d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}