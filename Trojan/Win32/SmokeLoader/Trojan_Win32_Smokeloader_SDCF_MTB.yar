
rule Trojan_Win32_Smokeloader_SDCF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SDCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 cf 8b 45 f0 c1 e8 05 89 45 fc 8b 55 dc 01 55 fc 33 f1 81 3d } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}