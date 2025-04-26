
rule TrojanDownloader_Win32_Bizdup_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Bizdup.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2f 6e 65 77 75 70 ?? 2e 74 78 74 00 } //1
		$a_01_1 = {d7 a2 b2 e1 b1 ed be af b8 e6 00 } //1
		$a_01_2 = {50 72 6f 74 65 63 74 65 64 73 74 6f 72 6c } //1 Protectedstorl
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 61 74 61 41 63 63 65 73 73 } //1 SOFTWARE\Microsoft\DataAccess
		$a_01_4 = {4d 53 44 4e 53 76 63 2e 64 6c 6c 00 4d 61 69 6e 74 65 6e 61 6e 63 65 00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}