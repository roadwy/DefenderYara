
rule TrojanDownloader_Win32_Allaple_gen_D{
	meta:
		description = "TrojanDownloader:Win32/Allaple.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {b8 a4 a9 40 00 e8 90 01 02 ff ff b8 a8 a9 40 00 e8 90 01 02 ff ff b8 ac a9 40 00 e8 90 01 02 ff ff 33 c0 5a 59 59 64 89 10 68 90 01 02 40 00 c3 90 00 } //1
		$a_00_1 = {2f 69 72 73 5f 65 66 69 6c 6c 2e 70 68 70 } //1 /irs_efill.php
		$a_02_2 = {74 6d 70 64 6f 77 6e 33 90 01 01 2e 64 6c 6c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}