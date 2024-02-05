
rule Trojan_Win32_Chapak_DSK_MTB{
	meta:
		description = "Trojan:Win32/Chapak.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a 44 2a 02 88 44 24 11 8a 44 2a 03 8a c8 88 44 24 10 80 e1 f0 c0 e1 02 0a 0c 2a 81 3d 90 01 04 e9 05 00 00 88 4c 24 12 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}