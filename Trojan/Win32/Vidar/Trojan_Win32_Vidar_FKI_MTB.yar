
rule Trojan_Win32_Vidar_FKI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.FKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 f9 83 bd 04 fc ff ff 90 01 01 0f 43 b5 90 01 04 f7 e1 d1 ea 8d 04 52 2b c8 8a 84 0d 90 01 04 8b 8d 90 01 04 32 07 88 04 0e 41 89 8d 90 01 04 3b 8d 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}