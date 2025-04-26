
rule Trojan_Win32_Smokeloader_RA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fe cd 65 84 00 75 0f a1 ?? ?? ?? 00 05 31 a2 00 00 a3 ?? ?? ?? 00 81 3d ?? ?? ?? 00 41 01 00 00 75 21 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}