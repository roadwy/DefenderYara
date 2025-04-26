
rule TrojanDownloader_Win32_Aentdwn_B_bit{
	meta:
		description = "TrojanDownloader:Win32/Aentdwn.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 00 36 00 35 00 2e 00 32 00 32 00 37 00 2e 00 31 00 35 00 33 00 2e 00 31 00 38 00 31 00 2f 00 [0-2f] 75 00 70 00 64 00 61 00 74 00 65 00 } //1
		$a_01_1 = {43 00 47 00 49 00 46 00 61 00 73 00 74 00 53 00 51 00 4c 00 2e 00 65 00 78 00 65 00 } //1 CGIFastSQL.exe
		$a_01_2 = {53 00 71 00 6c 00 2e 00 62 00 61 00 74 00 } //1 Sql.bat
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}