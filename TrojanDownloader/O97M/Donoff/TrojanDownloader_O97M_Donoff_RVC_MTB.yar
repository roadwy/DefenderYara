
rule TrojanDownloader_O97M_Donoff_RVC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.RVC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 3a 2f 2f 63 6f 75 6c 64 6d 61 69 6c 61 75 74 68 2e 63 6f 6d 2f 7a 68 71 39 33 65 38 68 73 6a 39 33 37 39 33 38 39 32 33 37 38 68 68 78 68 62 2f 72 65 67 68 6a 6f 6b 5f 36 34 2e 64 6c 6c } //1 ttp://couldmailauth.com/zhq93e8hsj93793892378hhxhb/reghjok_64.dll
		$a_01_1 = {3d 67 65 6e 65 72 61 74 65 72 61 6e 64 6f 6d 73 74 72 69 6e 67 26 6d 69 64 28 63 68 61 72 73 2c 69 6e 74 28 72 6e 64 2a 6c 65 6e 28 63 68 61 72 73 29 29 2b 31 2c 31 29 6e 65 78 74 69 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 =generaterandomstring&mid(chars,int(rnd*len(chars))+1,1)nextiendfunction
		$a_01_2 = {73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 subauto_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}