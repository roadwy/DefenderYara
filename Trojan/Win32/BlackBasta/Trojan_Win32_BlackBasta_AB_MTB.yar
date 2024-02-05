
rule Trojan_Win32_BlackBasta_AB_MTB{
	meta:
		description = "Trojan:Win32/BlackBasta.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {33 c1 88 45 fe 0f b7 55 f8 8b 45 a0 0f b7 08 d3 fa 8b 4d b4 66 89 11 8b 55 c4 8b 02 8b 4d e4 d3 e0 89 45 88 8b 4d 94 8b 55 dc 8b 01 2b 02 } //00 00 
	condition:
		any of ($a_*)
 
}