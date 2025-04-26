
rule TrojanDownloader_Win32_Gendwnurl_BN_bit{
	meta:
		description = "TrojanDownloader:Win32/Gendwnurl.BN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {23 53 69 6e 67 6c 65 49 6e 73 74 61 6e 63 65 20 66 6f 72 63 65 0a 23 4e 6f 54 72 61 79 49 63 6f 6e 0a } //1
		$a_03_1 = {53 65 74 57 6f 72 6b 69 6e 67 44 69 72 2c 20 25 41 70 70 44 61 74 61 25 0a 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 68 74 74 70 3a 2f 2f 37 38 2e 31 34 30 2e 32 32 30 2e 31 37 35 2f [0-20] 2c [0-10] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}