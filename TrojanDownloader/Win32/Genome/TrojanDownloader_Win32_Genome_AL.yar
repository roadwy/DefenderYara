
rule TrojanDownloader_Win32_Genome_AL{
	meta:
		description = "TrojanDownloader:Win32/Genome.AL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 77 73 5f 69 6e 73 74 61 6c 6c 2e 6d 73 69 } //1 kws_install.msi
		$a_01_1 = {2f 6b 77 73 2e 36 67 67 00 00 2e 63 6e 2f 4b 57 53 49 6e 73 74 61 6c 6c 2e 6d 73 69 } //1
		$a_01_2 = {73 6f 66 74 2e 64 6f 79 6f 2e 63 6e 2f 73 6f 00 00 66 74 2f 64 6f 79 6f 5f 73 65 74 75 70 5f 31 30 30 37 5f } //1
		$a_01_3 = {2e 78 75 6e 6c 65 69 31 00 00 30 30 2e 63 6f 6d 2f 6d 73 6e 2f 73 6f 66 74 77 61 72 65 2f 70 61 72 74 6e 65 72 2f 32 6d 2f 63 70 73 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}