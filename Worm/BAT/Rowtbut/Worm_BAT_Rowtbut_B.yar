
rule Worm_BAT_Rowtbut_B{
	meta:
		description = "Worm:BAT/Rowtbut.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {42 6f 74 41 6e 74 77 6f 72 74 } //1 BotAntwort
		$a_01_1 = {42 6f 74 42 65 65 6e 64 65 6e } //1 BotBeenden
		$a_01_2 = {4d 53 4e 53 70 72 65 61 64 53 74 61 72 74 } //1 MSNSpreadStart
		$a_01_3 = {53 74 61 72 74 48 54 54 50 46 6c 6f 6f 64 } //1 StartHTTPFlood
		$a_01_4 = {53 74 61 72 74 49 43 4d 50 46 6c 6f 6f 64 } //1 StartICMPFlood
		$a_01_5 = {53 74 61 72 74 53 59 4e 46 6c 6f 6f 64 } //1 StartSYNFlood
		$a_00_6 = {42 00 65 00 72 00 65 00 69 00 74 00 21 00 } //1 Bereit!
		$a_00_7 = {3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 72 00 65 00 70 00 6c 00 79 00 26 00 68 00 77 00 69 00 64 00 3d 00 } //1 ?action=reply&hwid=
		$a_00_8 = {3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 67 00 65 00 74 00 63 00 6f 00 6d 00 6d 00 26 00 68 00 77 00 69 00 64 00 3d 00 } //1 ?action=getcomm&hwid=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=6
 
}