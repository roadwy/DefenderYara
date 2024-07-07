
rule TrojanDownloader_WinNT_Nepift_A{
	meta:
		description = "TrojanDownloader:WinNT/Nepift.A,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 65 77 41 70 70 6c 65 74 2e 6a 61 76 61 } //1 NewApplet.java
		$a_01_1 = {57 69 35 30 65 48 51 67 5a 57 4e 6f 62 79 42 } //1 Wi50eHQgZWNobyB
		$a_01_2 = {5a 6e 52 77 4c 6d 52 79 61 58 5a 6c 61 48 45 75 59 32 39 74 } //1 ZnRwLmRyaXZlaHEuY29t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}