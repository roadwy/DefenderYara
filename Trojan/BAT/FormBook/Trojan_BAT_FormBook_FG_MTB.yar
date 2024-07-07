
rule Trojan_BAT_FormBook_FG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {0a 13 04 72 90 01 03 70 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 72 90 01 03 70 6f 90 01 03 0a 13 05 08 09 18 17 8d 01 00 00 01 13 08 11 08 16 07 a2 11 08 28 90 01 03 0a 13 06 11 06 11 04 18 16 8d 01 00 00 01 28 90 01 03 0a 13 07 11 07 11 05 17 18 8d 01 00 00 01 13 09 11 09 16 16 8c 15 00 00 01 a2 11 09 28 90 01 03 0a 26 2a 90 00 } //10
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {76 65 63 72 79 70 74 } //1 vecrypt
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}
rule Trojan_BAT_FormBook_FG_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 30 34 31 30 62 62 39 61 2d 65 39 34 64 2d 34 35 34 34 2d 39 31 63 66 2d 61 64 39 34 34 32 65 33 30 65 65 62 } //20 $0410bb9a-e94d-4544-91cf-ad9442e30eeb
		$a_81_1 = {43 50 50 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //20 CPP.My.Resources
		$a_81_2 = {43 50 50 2e 55 43 5f 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 CPP.UC_Main.resources
		$a_81_3 = {43 6f 66 66 65 65 20 53 68 6f 70 2e 74 78 74 } //1 Coffee Shop.txt
		$a_81_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_7 = {42 69 74 6d 61 70 } //1 Bitmap
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=26
 
}