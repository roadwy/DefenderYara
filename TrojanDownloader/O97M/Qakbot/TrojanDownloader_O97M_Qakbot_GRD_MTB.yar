
rule TrojanDownloader_O97M_Qakbot_GRD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.GRD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 75 6c 6b 61 72 61 62 69 61 2e 78 79 7a 2f 78 7a 78 75 77 74 70 76 77 2f } //1 bulkarabia.xyz/xzxuwtpvw/
		$a_01_1 = {43 3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //1 C:\Gravity\Gravity2\Fiksat.exe
		$a_01_2 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //1 CreateDirectoryA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}