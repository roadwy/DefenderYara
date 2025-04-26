
rule TrojanDownloader_Win32_Banker_AC{
	meta:
		description = "TrojanDownloader:Win32/Banker.AC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 59 76 61 52 36 6d [0-40] 2f 69 6e 69 63 69 6f [0-80] 52 75 6e 44 6c 6c 33 32 2e 65 78 65 [0-40] 2c 6f 6e 6c 69 66 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}