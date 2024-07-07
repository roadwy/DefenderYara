
rule TrojanDownloader_Win32_Zlob_gen_CQ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CQ,SIGNATURE_TYPE_PEHSTR,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {30 22 20 21 26 3b 20 3d 30 3b 2a 3d 22 26 21 2e 06 30 } //10 ∰℠㬦㴠㬰㴪☢⸡〆
		$a_01_1 = {44 33 35 38 2d 34 38 41 33 2d 41 35 43 37 } //10 D358-48A3-A5C7
		$a_01_2 = {20 68 70 74 72 } //1  hptr
		$a_01_3 = {39 43 41 36 38 42 } //1 9CA68B
		$a_01_4 = {47 4f 4d 4f 44 52 49 } //1 GOMODRI
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=22
 
}