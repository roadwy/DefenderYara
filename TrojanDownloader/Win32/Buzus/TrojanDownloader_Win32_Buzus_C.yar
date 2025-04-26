
rule TrojanDownloader_Win32_Buzus_C{
	meta:
		description = "TrojanDownloader:Win32/Buzus.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 00 01 40 84 53 53 52 55 ff 15 } //1
		$a_01_1 = {77 2b 62 00 25 63 25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00 } //1
		$a_01_2 = {2f 73 62 2e 70 68 70 3f 69 64 3d 25 30 36 64 25 73 } //1 /sb.php?id=%06d%s
		$a_00_3 = {5c 73 70 72 78 78 2e 64 6c 6c 00 } //1
		$a_00_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}