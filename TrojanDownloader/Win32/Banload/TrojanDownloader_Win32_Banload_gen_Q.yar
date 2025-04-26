
rule TrojanDownloader_Win32_Banload_gen_Q{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!Q,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 83 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 dc } //4
		$a_01_1 = {0a 00 00 00 42 61 69 78 61 6e 64 6f 3a 20 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}