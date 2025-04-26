
rule Trojan_Win32_Smokeloader_GPAA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 df 33 d8 2b f3 8b d6 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}