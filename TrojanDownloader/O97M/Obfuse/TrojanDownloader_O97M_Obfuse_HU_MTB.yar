
rule TrojanDownloader_O97M_Obfuse_HU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 49 49 49 49 49 49 49 33 2c 20 22 52 75 6e 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 57 49 4e 44 4f 57 53 31 2e 4c 61 62 65 6c 31 2e 54 61 67 20 2b 20 22 20 22 20 26 20 57 49 4e 44 4f 57 53 31 2e 54 61 67 20 2b 20 22 20 22 2c 20 30 2c 20 46 61 6c 73 65 } //1 CallByName IIIIIII3, "Run", VbMethod, WINDOWS1.Label1.Tag + " " & WINDOWS1.Tag + " ", 0, False
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 57 49 4e 44 4f 57 53 31 2e 4c 61 62 65 6c 32 2e 54 61 67 29 } //1 CreateObject(WINDOWS1.Label2.Tag)
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 55 73 65 72 46 6f 72 6d 31 2c 20 22 53 68 6f 77 22 2c 20 56 62 4d 65 74 68 6f 64 } //1 CallByName UserForm1, "Show", VbMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}