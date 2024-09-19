
rule Trojan_Win32_Smokeloader_KAF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d6 33 c2 33 c1 2b f8 83 3d ?? ?? ?? ?? ?? c7 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}