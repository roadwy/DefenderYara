
rule Spammer_Win32_Cutwail_gen_C{
	meta:
		description = "Spammer:Win32/Cutwail.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {30 16 46 49 75 f4 83 65 fc 00 8d 48 1c 8b 55 fc 8a 19 ff 45 fc 8d 3c 10 8a 17 88 11 49 83 7d fc 0e 88 1f 72 e8 f6 45 f8 01 74 0b 33 c9 f6 14 08 } //3
		$a_01_1 = {81 3e 00 01 02 03 75 09 81 7e 04 04 05 06 07 74 03 46 eb ec } //1
		$a_00_2 = {62 6f 74 5f 69 64 3d 25 64 26 6d 6f 64 65 } //1 bot_id=%d&mode
		$a_00_3 = {62 00 25 00 64 00 2c 00 66 00 25 00 64 00 } //1 b%d,f%d
		$a_00_4 = {5c 5c 2e 5c 52 75 6e 74 69 6d 65 } //1 \\.\Runtime
		$a_00_5 = {53 63 72 69 70 74 6f 72 3a 20 53 75 63 63 65 73 73 20 69 6e 74 65 72 70 72 65 74 61 74 65 20 73 63 72 69 70 74 2e } //1 Scriptor: Success interpretate script.
		$a_00_6 = {46 61 69 6c 20 53 54 41 52 54 20 52 65 67 41 63 63 2e } //1 Fail START RegAcc.
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=3
 
}