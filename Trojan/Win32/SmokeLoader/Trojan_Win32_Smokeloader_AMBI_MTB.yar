
rule Trojan_Win32_Smokeloader_AMBI_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.AMBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}