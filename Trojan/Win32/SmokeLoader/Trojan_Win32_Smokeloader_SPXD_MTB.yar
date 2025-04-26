
rule Trojan_Win32_Smokeloader_SPXD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 30 04 0e 83 7c 24 18 0f 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}