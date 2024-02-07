
rule Worm_Win32_Boinberg_gen_A{
	meta:
		description = "Worm:Win32/Boinberg.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 0a 00 00 04 00 "
		
	strings :
		$a_03_0 = {6a 56 8b 45 0c ff 90 90 90 01 01 01 00 00 50 8b 45 0c ff 90 90 90 01 01 01 00 00 6a 00 6a 03 6a 2d 90 00 } //04 00 
		$a_01_1 = {c7 45 d0 51 ce db 25 66 c7 45 d4 8f 6c 66 c7 45 d6 72 4a } //01 00 
		$a_01_2 = {73 70 72 65 61 64 2e 75 73 62 } //01 00  spread.usb
		$a_01_3 = {75 70 64 61 74 65 2d 6d 64 35 } //01 00  update-md5
		$a_01_4 = {70 69 6e 67 66 72 65 71 } //01 00  pingfreq
		$a_01_5 = {62 6f 74 6b 69 6c 6c 65 72 } //01 00  botkiller
		$a_01_6 = {73 70 72 65 61 64 2e 6d 73 6e } //01 00  spread.msn
		$a_01_7 = {73 70 72 65 61 64 2e 72 61 72 7a 69 70 } //01 00  spread.rarzip
		$a_01_8 = {64 64 6f 73 2e 73 73 79 6e } //01 00  ddos.ssyn
		$a_01_9 = {5b 53 54 45 41 4c 45 52 5d 3a } //00 00  [STEALER]:
	condition:
		any of ($a_*)
 
}