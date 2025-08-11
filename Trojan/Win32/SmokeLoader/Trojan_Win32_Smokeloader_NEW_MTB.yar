
rule Trojan_Win32_Smokeloader_NEW_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.NEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0c 10 30 0c 17 8b 4c 24 28 42 39 d1 75 f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}