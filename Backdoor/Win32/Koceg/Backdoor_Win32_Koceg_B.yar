
rule Backdoor_Win32_Koceg_B{
	meta:
		description = "Backdoor:Win32/Koceg.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 f8 6e 75 0d ff 75 10 ff 75 0c e8 90 01 02 ff ff 59 59 ff b5 90 01 01 f7 ff ff ff 15 90 01 04 0f b7 c0 83 f8 15 0f 85 90 01 01 01 00 00 8b 45 0c 0f be 00 83 f8 55 75 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}