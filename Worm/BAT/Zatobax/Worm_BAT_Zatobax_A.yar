
rule Worm_BAT_Zatobax_A{
	meta:
		description = "Worm:BAT/Zatobax.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {07 91 05 61 9c 07 17 58 0b 07 03 04 58 fe 04 } //1
		$a_01_1 = {74 61 7a 62 6f 78 2e 7a 61 70 74 6f 2e 6f 72 67 2f 64 6f 77 6e 6c 6f 61 64 65 72 2f 6d 69 6e 65 72 2f 68 68 2e 65 78 65 } //1 tazbox.zapto.org/downloader/miner/hh.exe
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 68 68 2e 65 78 65 68 74 74 70 } //1 Microsoft\hh.exehttp
		$a_01_3 = {28 3e 00 00 0a 0a 06 0d 16 0c 2b 0e 09 08 9a 0b 07 28 23 00 00 06 08 17 d6 0c 08 09 8e b7 32 ec } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}