
rule Trojan_Win32_Smokeloader_SPZJ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 04 24 f0 43 03 00 83 04 24 0d a1 ?? ?? ?? ?? 0f af 04 24 81 3d ?? ?? ?? ?? 9e 13 00 00 a3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}