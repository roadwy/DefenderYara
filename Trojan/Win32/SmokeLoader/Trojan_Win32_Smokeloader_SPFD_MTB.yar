
rule Trojan_Win32_Smokeloader_SPFD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 31 45 f0 8b 45 e8 33 45 f0 2b d8 89 45 e8 8b c3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}