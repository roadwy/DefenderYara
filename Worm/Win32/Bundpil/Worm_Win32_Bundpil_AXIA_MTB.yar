
rule Worm_Win32_Bundpil_AXIA_MTB{
	meta:
		description = "Worm:Win32/Bundpil.AXIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 0f b6 93 ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 32 14 03 46 81 e6 ?? ?? ?? ?? 88 10 79 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}