
rule TrojanDownloader_Win32_Banload_AKS{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKS,SIGNATURE_TYPE_PEHSTR_EXT,40 01 2c 01 0b 00 00 "
		
	strings :
		$a_01_0 = {2f 61 74 6d 70 2e 7a 69 70 00 } //100
		$a_01_1 = {2f 6d 65 6d 62 72 6f 73 2e 70 68 70 00 } //100
		$a_01_2 = {2f 6e 69 63 68 61 6e 2e 7a 69 70 00 } //100
		$a_01_3 = {6d 65 67 61 69 6d 70 6f 72 74 73 30 35 2e 63 6f 6d } //20 megaimports05.com
		$a_01_4 = {74 6f 70 76 69 70 7a 30 31 2e 64 6f 6d 69 6e 69 6f 74 65 6d 70 6f 72 61 72 69 6f 2e 63 6f 6d } //20 topvipz01.dominiotemporario.com
		$a_01_5 = {61 6e 64 72 65 6c 75 63 61 72 6e 61 2e 77 65 62 31 30 32 2e 66 31 2e 6b 38 2e 63 6f 6d 2e 62 72 } //20 andrelucarna.web102.f1.k8.com.br
		$a_01_6 = {62 61 6c 61 64 61 67 79 6e 6e 69 67 68 74 2e 63 6f 6d } //20 baladagynnight.com
		$a_01_7 = {37 36 2e 37 33 2e 38 30 2e 39 38 2f 7e } //20 76.73.80.98/~
		$a_01_8 = {34 73 68 61 72 65 64 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 } //20 4shared.com/download
		$a_01_9 = {68 6f 73 74 78 30 30 31 31 2e 64 6f 6d 69 6e 69 6f 74 65 6d 70 6f 72 61 72 69 6f 2e 63 6f 6d } //20 hostx0011.dominiotemporario.com
		$a_01_10 = {31 30 37 2e 32 32 2e 31 35 38 2e 31 39 33 2f } //20 107.22.158.193/
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20+(#a_01_8  & 1)*20+(#a_01_9  & 1)*20+(#a_01_10  & 1)*20) >=300
 
}