
rule TrojanDownloader_Win32_Kangkio_A{
	meta:
		description = "TrojanDownloader:Win32/Kangkio.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 25 37 37 25 37 37 25 37 37 25 32 45 25 36 42 25 36 31 25 36 45 25 36 37 25 36 42 25 32 45 25 36 33 25 36 45 2f 25 36 31 25 33 33 25 32 45 25 36 38 25 37 34 25 36 44 } //1 http://%77%77%77%2E%6B%61%6E%67%6B%2E%63%6E/%61%33%2E%68%74%6D
		$a_00_1 = {66 75 63 6b 61 6c 6c 73 68 61 61 6c 6c } //1 fuckallshaall
		$a_00_2 = {77 2e 6b 61 6e 67 6b 2e 63 6e 2f } //1 w.kangk.cn/
		$a_03_3 = {b8 08 20 00 00 e8 ?? ?? 00 00 55 56 6a 01 6a 00 6a 00 68 44 30 40 00 68 3c 30 40 00 6a 00 ff 15 08 22 40 00 8b e8 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*2) >=4
 
}