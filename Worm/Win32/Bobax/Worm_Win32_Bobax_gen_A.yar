
rule Worm_Win32_Bobax_gen_A{
	meta:
		description = "Worm:Win32/Bobax.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 72 2e 57 65 62 } //01 00  Dr.Web
		$a_00_1 = {28 25 64 29 22 } //01 00  (%d)"
		$a_01_2 = {46 52 4f 4d 3a 20 3c 3e } //01 00  FROM: <>
		$a_01_3 = {3c 49 4d 47 } //01 00  <IMG
		$a_00_4 = {25 70 3a 20 28 25 64 29 20 25 73 } //01 00  %p: (%d) %s
		$a_00_5 = {50 72 69 6e 74 20 53 70 6f 6f 6c 65 72 20 53 65 72 76 69 63 65 } //01 00  Print Spooler Service
		$a_00_6 = {74 6f 20 72 65 67 69 73 74 72 79 3a 20 25 73 } //01 00  to registry: %s
		$a_00_7 = {73 65 72 76 65 72 20 28 25 73 29 } //02 00  server (%s)
		$a_01_8 = {45 48 4c 4f 20 6c 6f 63 61 6c 68 6f 73 74 } //01 00  EHLO localhost
		$a_00_9 = {73 6d 74 70 2d 72 65 6c 61 79 } //01 00  smtp-relay
		$a_00_10 = {2d 3d 5f 4e 65 78 74 50 61 72 74 5f 25 30 33 64 } //01 00  -=_NextPart_%03d
		$a_00_11 = {25 73 3a 20 73 65 6e 64 20 65 72 72 6f 72 } //02 00  %s: send error
		$a_00_12 = {63 7c 63 70 70 7c 6e 66 6f 7c 69 6e 66 6f 7c 68 } //01 00  c|cpp|nfo|info|h
		$a_00_13 = {55 53 45 52 20 25 73 } //01 00  USER %s
		$a_00_14 = {50 41 53 53 20 25 73 } //00 00  PASS %s
	condition:
		any of ($a_*)
 
}