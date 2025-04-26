
rule TrojanDownloader_Win32_Renos_GQ{
	meta:
		description = "TrojanDownloader:Win32/Renos.GQ,SIGNATURE_TYPE_PEHSTR,1a 00 1a 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //10 InternetConnectA
		$a_01_1 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //10 HttpSendRequestA
		$a_01_2 = {2f 63 6b 2e 70 68 70 } //2 /ck.php
		$a_01_3 = {25 73 2f 72 2e 70 68 70 3f 26 76 3d } //2 %s/r.php?&v=
		$a_01_4 = {46 6c 61 73 68 20 56 69 64 65 6f 20 4f 62 6a 65 63 74 } //1 Flash Video Object
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 25 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\%s
		$a_01_6 = {00 62 68 6f 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 戀潨搮汬䐀汬慃啮汮慯乤睯
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=26
 
}