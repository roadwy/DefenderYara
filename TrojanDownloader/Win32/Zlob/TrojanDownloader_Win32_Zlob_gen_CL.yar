
rule TrojanDownloader_Win32_Zlob_gen_CL{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CL,SIGNATURE_TYPE_PEHSTR_EXT,69 00 69 00 06 00 00 64 00 "
		
	strings :
		$a_01_0 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //02 00  搮汬䐀汬慃啮汮慯乤睯
		$a_01_1 = {38 31 34 42 2d 34 38 33 39 } //02 00  814B-4839
		$a_01_2 = {30 45 42 43 2d 34 44 38 39 } //01 00  0EBC-4D89
		$a_01_3 = {67 65 4c 69 73 74 5f 41 64 64 } //01 00  geList_Add
		$a_01_4 = {32 30 58 43 30 30 } //01 00  20XC00
		$a_01_5 = {76 20 2d 20 6e 61 73 68 } //00 00  v - nash
	condition:
		any of ($a_*)
 
}