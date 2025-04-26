
rule Trojan_Win32_Smokeloader_HTZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 8b c7 c1 e8 05 03 d7 89 45 f8 8b 45 dc 01 45 f8 8b f7 c1 e6 04 03 75 d8 33 f2 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}