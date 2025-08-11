
rule Trojan_Win32_Smokeloader_EAVZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.EAVZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 95 14 f7 ff ff 83 c2 04 89 95 14 f7 ff ff 3b 17 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}