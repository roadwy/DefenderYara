
rule TrojanDownloader_Win32_Strictor_AC_MTB{
	meta:
		description = "TrojanDownloader:Win32/Strictor.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 30 00 2e 00 39 00 37 00 2e 00 31 00 39 00 35 00 2e 00 31 00 34 00 36 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 } //1 http://180.97.195.146/uploads/
		$a_01_1 = {44 65 73 6b 74 6f 70 5c 53 63 5c 52 65 6c 65 61 73 65 5c 53 63 2e 70 64 62 } //1 Desktop\Sc\Release\Sc.pdb
		$a_01_2 = {53 00 65 00 74 00 2d 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 3a 00 5c 00 62 00 2a 00 7b 00 2e 00 2b 00 } //1 Set-Cookie:\b*{.+
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}