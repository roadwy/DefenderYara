
rule Trojan_Win32_Smokeloader_GPAE_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GPAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 4d fc 8b 45 f8 33 4d f0 03 45 cc 33 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}