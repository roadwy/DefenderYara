
rule Worm_Win32_Bundpil_AWIA_MTB{
	meta:
		description = "Worm:Win32/Bundpil.AWIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 43 8a 83 ?? ?? ?? ?? 32 04 0a 41 ff 8d ?? ?? ?? ?? 88 41 ff 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}