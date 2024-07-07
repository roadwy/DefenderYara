
rule TrojanDownloader_Win32_Delf_IE{
	meta:
		description = "TrojanDownloader:Win32/Delf.IE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 5c 38 ff 80 fb 30 75 90 14 8b 45 fc 80 fb 7a 75 90 00 } //1
		$a_00_1 = {32 57 31 50 31 53 74 47 32 59 31 45 31 51 31 54 32 5a 31 50 31 43 74 46 } //1 2W1P1StG2Y1E1Q1T2Z1P1CtF
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}