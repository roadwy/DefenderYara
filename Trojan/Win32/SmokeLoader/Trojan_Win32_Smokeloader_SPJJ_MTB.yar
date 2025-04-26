
rule Trojan_Win32_Smokeloader_SPJJ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPJJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 45 e8 8b 45 e8 33 d0 89 45 fc 89 55 f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}