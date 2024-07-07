
rule TrojanDownloader_BAT_Balamid_C{
	meta:
		description = "TrojanDownloader:BAT/Balamid.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 6c 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //1 \lsm.exe
		$a_01_1 = {2f 00 65 00 78 00 63 00 32 00 2e 00 74 00 78 00 74 00 } //1 /exc2.txt
		$a_01_2 = {62 00 61 00 67 00 6c 00 61 00 6e 00 6d 00 61 00 64 00 69 00 } //1 baglanmadi
		$a_01_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 31 00 32 00 2e 00 31 00 32 00 39 00 2e 00 33 00 31 00 2e 00 36 00 37 00 } //1 http://212.129.31.67
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}