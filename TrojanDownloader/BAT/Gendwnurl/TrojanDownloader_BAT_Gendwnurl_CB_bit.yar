
rule TrojanDownloader_BAT_Gendwnurl_CB_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.CB!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 00 3a 00 5c 00 5f 00 78 00 66 00 61 00 63 00 65 00 [0-10] 2e 00 65 00 78 00 65 00 } //1
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6d 00 64 00 39 00 65 00 2e 00 61 00 33 00 69 00 31 00 76 00 76 00 76 00 2e 00 66 00 65 00 74 00 65 00 62 00 6f 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 78 00 73 00 6f 00 [0-10] 2e 00 65 00 78 00 65 00 } //1
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 74 75 61 6e 6e 5c 4f 6e 65 44 72 69 76 65 5c 58 53 4f 46 54 5c 58 46 61 63 65 5c 53 45 54 55 50 5c 41 75 74 6f 55 70 64 61 74 65 58 66 61 63 65 5c 58 66 61 63 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 41 75 74 6f 55 70 64 61 74 65 58 66 61 63 65 2e 70 64 62 } //1 C:\Users\tuann\OneDrive\XSOFT\XFace\SETUP\AutoUpdateXface\Xface\obj\Debug\AutoUpdateXface.pdb
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}