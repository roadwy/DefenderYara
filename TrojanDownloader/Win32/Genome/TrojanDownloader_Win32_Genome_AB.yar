
rule TrojanDownloader_Win32_Genome_AB{
	meta:
		description = "TrojanDownloader:Win32/Genome.AB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 36 30 72 70 2e 65 78 65 } //01 00  360rp.exe
		$a_01_1 = {33 36 30 73 64 2e 65 78 65 } //01 00  360sd.exe
		$a_01_2 = {65 6b 72 6e 2e 65 78 65 } //01 00  ekrn.exe
		$a_01_3 = {5c 73 73 61 71 2e 65 78 65 } //01 00  \ssaq.exe
		$a_01_4 = {64 6e 66 75 75 2e 33 33 32 32 2e 6f 72 67 2f 64 79 2f 71 69 61 6e 67 2e 65 78 65 } //01 00  dnfuu.3322.org/dy/qiang.exe
		$a_01_5 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 61 73 65 78 2e 65 78 65 } //00 00  C:\windows\asex.exe
	condition:
		any of ($a_*)
 
}