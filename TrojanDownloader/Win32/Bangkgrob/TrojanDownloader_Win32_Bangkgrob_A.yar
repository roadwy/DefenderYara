
rule TrojanDownloader_Win32_Bangkgrob_A{
	meta:
		description = "TrojanDownloader:Win32/Bangkgrob.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 "
		
	strings :
		$a_01_0 = {70 3a 2f 2f 66 69 74 61 70 72 65 74 61 2e 63 6f 6d } //4 p://fitapreta.com
		$a_01_1 = {69 6e 64 65 78 2e 70 68 70 2f 64 6f 77 6e 6c 6f 61 64 63 6f 75 6e 74 2f 66 75 67 69 74 69 76 6f 2d 31 30 30 } //4 index.php/downloadcount/fugitivo-100
		$a_01_2 = {77 2e 74 72 61 6a 61 6e 6f 61 6c 6d 65 69 64 61 2e 63 6f 6d 2e 62 72 } //4 w.trajanoalmeida.com.br
		$a_01_3 = {2f 43 6c 69 65 6e 74 65 73 2f 49 6e 73 74 61 6c 2e 62 63 6b } //2 /Clientes/Instal.bck
		$a_01_4 = {2f 6f 6c 64 2e 62 63 6b } //1 /old.bck
		$a_01_5 = {2f 76 69 73 74 61 2e 62 63 6b } //1 /vista.bck
		$a_01_6 = {2f 54 61 73 6b 2e 62 63 6b } //1 /Task.bck
		$a_01_7 = {2f 78 70 2e 62 63 6b } //1 /xp.bck
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=9
 
}