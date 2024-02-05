
rule Trojan_Win32_Zlob_AT{
	meta:
		description = "Trojan:Win32/Zlob.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 85 f0 fd ff ff 50 e8 90 01 04 90 02 02 59 59 f7 d8 1b c0 f7 d8 88 85 90 01 01 fd ff ff 90 00 } //01 00 
		$a_03_1 = {eb 07 8b 45 c4 40 89 45 c4 8b 45 c4 3b 45 ec 73 90 03 01 01 2a 2b ff 75 0c e8 90 01 01 fe ff ff 90 02 66 89 45 c0 0f b7 45 c0 35 90 01 02 00 00 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}