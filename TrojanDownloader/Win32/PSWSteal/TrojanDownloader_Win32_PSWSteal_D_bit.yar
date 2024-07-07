
rule TrojanDownloader_Win32_PSWSteal_D_bit{
	meta:
		description = "TrojanDownloader:Win32/PSWSteal.D!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 68 74 74 70 73 3a 2f 2f 67 6f 6f 2e 67 6c 2f } //1 URLDownloadToFile, https://goo.gl/
		$a_01_1 = {52 65 67 57 72 69 74 65 2c 20 52 45 47 5f 53 5a 2c 20 48 4b 43 55 5c 54 69 67 65 72 54 72 61 64 65 } //1 RegWrite, REG_SZ, HKCU\TigerTrade
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}