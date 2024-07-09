
rule TrojanDownloader_Win32_Cavitate_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Cavitate.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c8 81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 8a 91 ?? ?? ?? 10 8a (88|98) ?? ?? ?? 10 32 90 03 01 01 ca da 88 (88|98) ?? ?? ?? 10 40 3d ?? ?? 00 00 7c d5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}