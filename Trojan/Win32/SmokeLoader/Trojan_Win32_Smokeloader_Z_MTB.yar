
rule Trojan_Win32_Smokeloader_Z_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e8 03 d7 89 45 f8 8b 45 d8 01 45 f8 8b 45 f8 8d 4d f0 33 c2 8b 55 f4 33 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}