
rule TrojanDownloader_Win32_Horst_K{
	meta:
		description = "TrojanDownloader:Win32/Horst.K,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 04 01 00 00 68 50 ac 40 00 68 ?? ?? 40 00 ff 15 ?? 80 40 00 ([0-02] ff d6 68 ?? ?? 40 00 68 ?|? ?? 40 00 )} //1
		$a_02_1 = {68 04 01 00 00 68 30 ac 40 00 68 ?? ?? 40 00 ff 15 ?? 80 40 00 ff d6 68 ?? ?? 40 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}