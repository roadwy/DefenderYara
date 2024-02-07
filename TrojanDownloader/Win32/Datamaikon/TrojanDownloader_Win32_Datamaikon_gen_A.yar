
rule TrojanDownloader_Win32_Datamaikon_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Datamaikon.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 70 64 61 74 65 2e 6b 6f 6e 61 6d 69 64 61 74 61 2e 63 6f 6d 2f 74 65 73 74 2f } //01 00  update.konamidata.com/test/
		$a_01_1 = {50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 42 61 73 69 63 } //01 00  Proxy-Authorization:Basic
		$a_01_2 = {6d 79 41 67 65 6e 74 } //01 00  myAgent
		$a_01_3 = {41 76 61 6c 69 61 62 6c 65 20 64 61 74 61 3a 25 75 20 62 79 74 65 73 } //01 00  Avaliable data:%u bytes
		$a_03_4 = {99 b9 10 27 00 00 f7 f9 8d 84 24 18 01 00 00 52 68 5c e6 41 00 8d 94 24 a0 00 00 00 52 68 50 e6 41 00 50 e8 90 01 02 00 00 8d 8c 24 ac 03 00 00 51 8d 54 24 30 52 8d 84 24 34 01 00 00 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}