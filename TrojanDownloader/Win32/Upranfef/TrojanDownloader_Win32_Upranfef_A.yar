
rule TrojanDownloader_Win32_Upranfef_A{
	meta:
		description = "TrojanDownloader:Win32/Upranfef.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6f 70 65 6e 00 [0-07] 68 74 74 70 3a 2f 2f [0-30] 2f 75 70 64 61 74 2e 65 78 65 00 [0-07] 25 73 5c 25 73 2e 65 78 65 } //1
		$a_03_1 = {99 59 f7 f9 8d 45 08 50 53 83 c2 61 89 55 08 e8 ?? ?? ?? ?? 59 4f 59 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}