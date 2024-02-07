
rule TrojanSpy_Win32_Clentil{
	meta:
		description = "TrojanSpy:Win32/Clentil,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 63 6c 69 65 6e 74 2e 68 74 6d 6c } //01 00  /client.html
		$a_01_1 = {26 63 6d 5b 25 64 5d 3d 4f 75 74 6c 6f 6f 6b } //01 00  &cm[%d]=Outlook
		$a_01_2 = {26 63 6d 5b 25 64 5d 3d 54 68 65 42 61 74 } //01 00  &cm[%d]=TheBat
		$a_01_3 = {26 73 72 63 5b 25 64 5d 3d 65 6d 61 69 6c 67 72 61 62 62 65 72 5f 25 73 } //01 00  &src[%d]=emailgrabber_%s
		$a_01_4 = {26 73 72 63 5b 25 64 5d 3d 66 74 70 67 72 61 62 62 65 72 5f 25 73 } //01 00  &src[%d]=ftpgrabber_%s
		$a_01_5 = {46 54 50 44 65 74 65 63 74 6f 72 } //01 00  FTPDetector
		$a_01_6 = {26 71 75 65 72 79 3d 73 6e 69 66 66 26 64 61 74 61 3d } //01 00  &query=sniff&data=
		$a_01_7 = {23 23 42 4f 54 5f 49 44 5f 45 58 49 53 54 23 23 23 79 65 73 23 23 23 42 4f 54 5f 49 44 5f 45 58 49 53 54 5f 45 4e 44 23 23 23 } //00 00  ##BOT_ID_EXIST###yes###BOT_ID_EXIST_END###
	condition:
		any of ($a_*)
 
}