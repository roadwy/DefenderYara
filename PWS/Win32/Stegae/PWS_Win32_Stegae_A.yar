
rule PWS_Win32_Stegae_A{
	meta:
		description = "PWS:Win32/Stegae.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 67 61 74 65 2e 70 68 70 00 } //01 00 
		$a_00_1 = {5c 50 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //01 00  \Pbk\rasphone.pbk
		$a_00_2 = {52 00 61 00 73 00 44 00 69 00 61 00 6c 00 50 00 61 00 72 00 61 00 6d 00 73 00 21 00 25 00 73 00 23 00 30 00 } //01 00  RasDialParams!%s#0
		$a_03_3 = {6a 02 66 89 45 90 01 01 ff 15 90 01 04 89 90 03 04 06 45 90 01 01 85 90 01 02 ff ff 83 f8 ff 75 90 01 01 32 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}