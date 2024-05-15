
rule Trojan_Win32_Zenpak_ASAD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 0c 0b 8b 55 e8 8b 75 d0 32 0c 32 88 0d 90 01 04 c7 05 90 01 04 d7 13 00 00 c7 05 90 01 04 c9 1a 00 00 8b 55 e4 88 0c 32 8b 4d f0 39 cf 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}