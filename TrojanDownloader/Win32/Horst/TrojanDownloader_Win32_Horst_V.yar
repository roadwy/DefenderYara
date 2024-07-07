
rule TrojanDownloader_Win32_Horst_V{
	meta:
		description = "TrojanDownloader:Win32/Horst.V,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 61 75 6e 63 31 7c 25 73 7c 25 64 7c 25 64 00 } //1 慬湵ㅣ╼米搥╼d
		$a_01_1 = {73 65 65 6b 2e 6f 72 67 2f 3f 72 32 3d 00 } //1 敳步漮杲㼯㉲=
		$a_01_2 = {26 72 3d 6a 63 61 64 00 } //1 爦樽慣d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}