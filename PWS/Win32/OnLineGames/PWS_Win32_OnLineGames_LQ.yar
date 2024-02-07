
rule PWS_Win32_OnLineGames_LQ{
	meta:
		description = "PWS:Win32/OnLineGames.LQ,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 4d 41 4c 2b 48 4f 53 54 3a 25 73 2b 49 50 3a 25 73 2b 4e 41 4d 45 3a 25 73 2b 50 41 53 53 3a 25 73 2b 56 65 72 3a 25 73 } //01 00  GMAL+HOST:%s+IP:%s+NAME:%s+PASS:%s+Ver:%s
		$a_01_1 = {59 41 48 4f 2b 48 4f 53 54 3a 25 73 2b 49 50 3a 25 73 2b 4e 41 4d 45 3a 25 73 2b 50 41 53 53 3a 25 73 2b 56 65 72 3a 25 73 } //01 00  YAHO+HOST:%s+IP:%s+NAME:%s+PASS:%s+Ver:%s
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 74 77 2e 67 61 73 68 2e 67 61 6d 61 6e 69 61 2e 63 6f 6d 2f 47 41 53 48 4c 6f 67 69 6e 2e 61 73 70 78 } //01 00  https://tw.gash.gamania.com/GASHLogin.aspx
		$a_01_3 = {50 4f 53 54 20 25 73 3f 43 4f 44 45 3d 25 73 20 48 54 54 50 2f 31 2e 31 } //00 00  POST %s?CODE=%s HTTP/1.1
	condition:
		any of ($a_*)
 
}