
rule TrojanDownloader_Win32_Banload_AEX{
	meta:
		description = "TrojanDownloader:Win32/Banload.AEX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 b8 0b 00 00 e8 ?? ?? ?? ?? a1 ?? ?? ?? 00 8b 00 e8 ?? ?? ?? ?? c3 [0-07] 3a 5c 57 69 6e 64 6f 77 73 5c [0-10] 2e 65 78 65 00 [0-05] 68 74 74 70 3a 2f 2f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}