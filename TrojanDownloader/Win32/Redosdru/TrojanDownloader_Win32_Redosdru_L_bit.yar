
rule TrojanDownloader_Win32_Redosdru_L_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.L!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 11 04 ?? 34 ?? 88 04 11 83 c1 01 3b ce 7c } //1
		$a_03_1 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}