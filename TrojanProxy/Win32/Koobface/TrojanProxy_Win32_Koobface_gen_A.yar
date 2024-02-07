
rule TrojanProxy_Win32_Koobface_gen_A{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0e 00 00 03 00 "
		
	strings :
		$a_01_0 = {70 72 6f 63 65 73 73 2d 64 6f 6d 61 69 6e } //03 00  process-domain
		$a_01_1 = {70 72 6f 25 73 61 69 6e 00 00 00 00 63 65 73 73 } //03 00 
		$a_01_2 = {25 73 6f 25 73 61 69 6e 00 00 00 00 70 72 00 } //03 00 
		$a_01_3 = {70 72 6f 63 65 73 73 2d 63 6c 69 63 6b 73 } //02 00  process-clicks
		$a_01_4 = {2f 73 65 61 72 63 68 2e 70 68 70 3f 70 3d 25 30 34 64 } //02 00  /search.php?p=%04d
		$a_01_5 = {43 55 2d 25 64 3a } //02 00  CU-%d:
		$a_01_6 = {49 47 59 4d 41 53 } //01 00  IGYMAS
		$a_01_7 = {75 73 65 72 5f 70 72 65 66 28 22 6e 65 74 77 6f 72 6b 2e 70 72 6f 78 79 2e 68 74 74 70 5f 70 6f 72 74 } //01 00  user_pref("network.proxy.http_port
		$a_01_8 = {65 72 76 65 72 00 68 74 74 70 3d 31 32 37 2e 30 } //04 00  牥敶r瑨灴ㄽ㜲〮
		$a_03_9 = {6a 04 eb c1 56 68 90 01 04 57 e8 90 01 02 ff ff f6 d8 90 00 } //02 00 
		$a_01_10 = {6a 1e 51 68 98 01 22 00 } //02 00 
		$a_01_11 = {68 9e 1b 00 00 } //01 00 
		$a_01_12 = {c6 45 08 55 c6 45 09 0d } //01 00 
		$a_01_13 = {c6 45 fc d5 c6 45 fd ae } //00 00 
	condition:
		any of ($a_*)
 
}