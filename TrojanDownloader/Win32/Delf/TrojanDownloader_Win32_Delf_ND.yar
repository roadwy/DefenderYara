
rule TrojanDownloader_Win32_Delf_ND{
	meta:
		description = "TrojanDownloader:Win32/Delf.ND,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 64 3a 20 63 6d 64 3d 25 73 20 68 6f 75 72 3d 25 73 3a 25 73 3a 25 73 20 53 79 73 74 65 6d 54 69 6d 65 2e 77 48 6f 75 72 3d 20 25 64 3a 25 64 3a 25 64 20 70 61 72 61 6d 3d 20 25 73 20 69 6e 73 74 61 6c 6c 3d 25 64 20 44 6f 77 6e 6c 6f 61 64 3d 25 64 20 48 61 76 65 45 78 65 63 75 74 65 3d 25 64 } //5 %d: cmd=%s hour=%s:%s:%s SystemTime.wHour= %d:%d:%d param= %s install=%d Download=%d HaveExecute=%d
		$a_01_1 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 6e 65 77 20 69 6e 73 74 61 6c 6c 20 61 74 6f 6d 2c 77 72 69 74 65 20 72 65 67 69 73 74 65 72 79 20 61 6e 64 20 77 72 69 74 65 20 62 61 63 6b 20 6c 6f 67 20 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d } //4 =========new install atom,write registery and write back log ============
		$a_01_2 = {68 74 74 70 3a 2f 2f 33 33 33 2e 65 32 36 2e 63 6e 2f 61 64 6d 69 6e 2f 77 72 69 74 65 6c 6f 67 2e 61 73 70 78 3f 41 63 74 69 6f 6e 3d 25 73 26 4f 77 6e 65 72 3d 25 73 26 49 50 3d 25 73 26 55 73 65 72 6e 61 6d 65 3d 25 73 26 43 6f 6d 70 75 74 65 72 4e 61 6d 65 3d 25 73 26 4f 73 3d 25 73 26 4c 6f 67 44 61 74 65 3d 25 73 26 4d 65 6d 6f 3d 25 73 } //4 http://333.e26.cn/admin/writelog.aspx?Action=%s&Owner=%s&IP=%s&Username=%s&ComputerName=%s&Os=%s&LogDate=%s&Memo=%s
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4) >=13
 
}