
rule TrojanDownloader_Win32_Redosdru_I_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.I!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 40 4e 75 } //1
		$a_03_1 = {44 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 46 c6 44 24 ?? 75 c6 44 24 ?? 55 c6 44 24 ?? 70 c6 44 24 ?? 67 c6 44 24 ?? 72 c6 44 24 ?? 61 c6 44 24 ?? 64 c6 44 24 ?? 72 c6 44 24 ?? 73 } //1
		$a_03_2 = {40 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 } //1
		$a_03_3 = {53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? 53 c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}