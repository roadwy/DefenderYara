
rule TrojanDownloader_Win32_Adload_CA{
	meta:
		description = "TrojanDownloader:Win32/Adload.CA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 73 6f 63 6b 3d 31 } //1 &sock=1
		$a_01_1 = {73 69 64 65 62 61 72 5f 63 6c 69 63 6b 2e 61 73 70 } //1 sidebar_click.asp
		$a_01_2 = {2f 73 40 69 64 40 65 62 61 40 72 2e 61 40 73 24 70 3f 62 40 6e 3d 24 30 26 71 24 79 3d } //1 /s@id@eba@r.a@s$p?b@n=$0&q$y=
		$a_03_3 = {2f 2f 6f 24 76 40 65 72 74 40 [0-03] 2e 63 6f 6d 2f 6f ?? ?? ?? 2f 6f 76 6e 5f 6f 2e 61 40 73 24 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}