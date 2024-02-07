
rule Worm_Win32_Wootbot_gen_B{
	meta:
		description = "Worm:Win32/Wootbot.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 66 74 70 2e 65 78 65 20 2d 69 20 20 67 65 74 } //01 00  tftp.exe -i  get
		$a_00_1 = {66 6f 72 73 79 6e } //01 00  forsyn
		$a_00_2 = {53 63 61 6e 28 25 73 29 3a 20 25 73 20 50 6f 72 74 20 53 63 61 6e 20 25 73 3a 25 64 } //01 00  Scan(%s): %s Port Scan %s:%d
		$a_00_3 = {66 74 70 20 2d 6e 20 2d 76 20 2d 73 3a } //01 00  ftp -n -v -s:
		$a_00_4 = {5b 25 73 5d 20 46 69 6e 69 73 68 65 64 20 66 6c 6f 6f 64 69 6e 67 20 25 73 20 25 64 20 54 69 6d 65 73 } //01 00  [%s] Finished flooding %s %d Times
		$a_00_5 = {57 6f 6f 74 00 } //01 00 
		$a_00_6 = {61 7c 62 7c 63 7c 64 7c 65 7c 66 7c 67 7c 68 7c 69 7c 6a 7c 6b 7c 6c 7c 6d 7c 6e } //01 00  a|b|c|d|e|f|g|h|i|j|k|l|m|n
		$a_01_7 = {6a 00 6a 0b 6a 03 6a 09 6a 0e 6a 04 6a 0e 6a 12 6a 4f 8d 54 24 } //00 00 
	condition:
		any of ($a_*)
 
}