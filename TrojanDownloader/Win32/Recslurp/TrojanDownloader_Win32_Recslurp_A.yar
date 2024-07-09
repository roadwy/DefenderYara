
rule TrojanDownloader_Win32_Recslurp_A{
	meta:
		description = "TrojanDownloader:Win32/Recslurp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 3b 8b 55 0c 0f be 14 32 31 d0 83 c0 20 } //1
		$a_01_1 = {8b 45 fc 8b 50 3c 03 56 54 52 50 ff 75 f8 e8 } //1
		$a_03_2 = {c6 06 aa 6a 00 6a 01 56 ff 75 f4 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c6 06 bb } //1
		$a_01_3 = {6a 3b 89 d8 40 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}