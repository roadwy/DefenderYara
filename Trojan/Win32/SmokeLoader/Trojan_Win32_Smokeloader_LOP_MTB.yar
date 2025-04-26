
rule Trojan_Win32_Smokeloader_LOP_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.LOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75 06 ff 15 ?? ?? ?? ?? 8b 4d fc 33 ce 2b f9 89 7d f0 8b 45 d8 29 45 f8 83 6d ?? 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}