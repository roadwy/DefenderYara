
rule TrojanDownloader_Win32_Genome_Z{
	meta:
		description = "TrojanDownloader:Win32/Genome.Z,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 5c 38 ff 80 e3 0f b8 ?? ?? ?? ?? 0f b6 44 30 ff 24 0f 32 d8 } //1
		$a_00_1 = {5c 6e 74 73 79 73 64 6c 6c 2e 74 6d 70 } //1 \ntsysdll.tmp
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}