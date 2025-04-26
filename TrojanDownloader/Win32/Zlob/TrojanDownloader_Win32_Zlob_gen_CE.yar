
rule TrojanDownloader_Win32_Zlob_gen_CE{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {a0 66 00 10 32 4c 24 ?? 48 88 88 } //1
		$a_01_1 = {72 65 61 6c 2e 64 6c 6c 00 44 6c 6c } //1 敲污搮汬䐀汬
		$a_00_2 = {72 00 65 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 } //1 res://%s
		$a_00_3 = {72 00 25 00 73 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 } //1 r%ss://%s
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}