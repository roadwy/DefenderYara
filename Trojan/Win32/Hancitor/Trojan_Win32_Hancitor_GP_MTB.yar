
rule Trojan_Win32_Hancitor_GP_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b ca 89 0d 90 01 04 ba 90 01 04 c7 05 90 01 04 00 00 00 00 0f b6 0d 90 01 04 03 cf 02 c2 04 08 66 81 fb 90 01 02 8d ac 69 90 01 04 8b 0e a2 90 01 04 75 90 01 01 0f b7 05 90 01 04 2b e8 81 c1 90 01 04 8b c7 2b c2 89 0e 83 e8 90 01 01 83 c6 04 83 6c 24 90 01 01 01 89 0d 90 01 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}