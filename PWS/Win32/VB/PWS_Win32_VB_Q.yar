
rule PWS_Win32_VB_Q{
	meta:
		description = "PWS:Win32/VB.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 00 78 00 31 00 2e 00 6d 00 61 00 69 00 6c 00 2e 00 79 00 61 00 68 00 6f 00 6f 00 2e 00 63 00 6f 00 6d 00 } //01 00  mx1.mail.yahoo.com
		$a_01_1 = {74 6d 72 47 45 54 4b 45 59 } //01 00  tmrGETKEY
		$a_03_2 = {50 51 c7 45 90 01 01 01 80 ff ff c7 45 90 01 01 02 80 00 00 ff 15 90 01 04 66 85 c0 0f 84 90 01 02 00 00 66 83 ff 01 75 0a ba 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}