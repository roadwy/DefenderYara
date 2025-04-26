
rule TrojanDownloader_Win32_Banload_AYY{
	meta:
		description = "TrojanDownloader:Win32/Banload.AYY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 63 65 73 73 6f 2e 70 68 70 00 } //1
		$a_01_1 = {66 6c 61 73 68 70 6c 61 79 65 72 70 6c 75 67 69 6e } //1 flashplayerplugin
		$a_01_2 = {3a 2e 2e 20 47 62 50 6c 75 67 69 6e 2e 2e 3a } //1 :.. GbPlugin..:
		$a_01_3 = {3a 2e 2e 20 41 4e 54 49 56 49 52 55 53 20 2e 2e 3a } //1 :.. ANTIVIRUS ..:
		$a_01_4 = {3a 2e 2e 56 45 52 53 41 4f 20 4b 6c 2e 2e 3a } //1 :..VERSAO Kl..:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}