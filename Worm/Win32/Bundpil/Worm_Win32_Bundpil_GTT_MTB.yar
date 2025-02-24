
rule Worm_Win32_Bundpil_GTT_MTB{
	meta:
		description = "Worm:Win32/Bundpil.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 0f b6 93 ?? ?? ?? ?? 8b 9d ?? ?? ?? ?? 32 14 03 41 81 e1 ff ?? ?? ?? 88 10 79 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}