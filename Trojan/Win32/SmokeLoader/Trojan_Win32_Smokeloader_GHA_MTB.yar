
rule Trojan_Win32_Smokeloader_GHA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 44 24 90 01 01 33 44 24 90 01 01 33 c8 51 8b c6 89 4c 24 90 01 01 e8 90 01 04 81 44 24 90 01 01 47 86 c8 61 83 6c 24 90 01 02 8b f0 89 74 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}