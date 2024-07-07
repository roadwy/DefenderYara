
rule TrojanDownloader_BAT_AsyncRAT_BZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 03 06 03 8e 69 5d 91 61 d2 9c 06 17 58 } //2
		$a_01_1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //2 C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}