
rule Trojan_Win32_Smokeloader_GHV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 03 cb 8b 44 24 90 01 01 31 44 24 90 01 01 8b 54 24 90 01 01 52 51 8d 44 24 90 01 01 50 e8 90 01 04 8b 44 24 90 01 01 29 44 24 90 01 01 81 44 24 90 01 01 47 86 c8 61 83 ed 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}