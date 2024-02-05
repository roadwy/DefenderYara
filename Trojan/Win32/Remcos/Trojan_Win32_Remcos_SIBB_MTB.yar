
rule Trojan_Win32_Remcos_SIBB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SIBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 85 db 7e 90 01 01 c7 05 90 01 08 a1 90 01 04 e8 90 01 04 50 b8 90 01 04 2b 45 90 01 01 5a 8b ca 99 f7 f9 8b 45 90 01 01 8b 0d 90 01 04 0f b6 44 08 90 01 01 03 d0 8d 45 90 01 01 e8 39 0b fa 90 01 01 8b 55 90 01 01 8b c6 e8 90 01 04 ff 05 90 01 04 4b 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}