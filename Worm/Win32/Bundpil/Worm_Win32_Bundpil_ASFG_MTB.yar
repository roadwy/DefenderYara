
rule Worm_Win32_Bundpil_ASFG_MTB{
	meta:
		description = "Worm:Win32/Bundpil.ASFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4a 81 ca 00 ff ff ff 42 89 95 ?? ?? ff ff 8b 55 fc 03 95 ?? ?? ff ff 0f b6 02 8b 8d ?? ?? ff ff 0f b6 91 ?? ?? ?? ?? 33 c2 8b 4d ?? 03 8d ?? ?? ff ff 88 01 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}