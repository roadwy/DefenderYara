
rule Trojan_Win32_GandCrab_DSK_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 55 fe 08 5d ?? 8a c2 83 25 ?? ?? ?? ?? 00 24 fc c0 e0 04 0a f8 81 3d ?? ?? ?? ?? 38 13 00 00 88 7d fc 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}