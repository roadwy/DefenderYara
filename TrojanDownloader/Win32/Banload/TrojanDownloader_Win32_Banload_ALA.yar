
rule TrojanDownloader_Win32_Banload_ALA{
	meta:
		description = "TrojanDownloader:Win32/Banload.ALA,SIGNATURE_TYPE_PEHSTR_EXT,04 01 ffffffdc 00 09 00 00 "
		
	strings :
		$a_01_0 = {2d 20 5d 75 65 2e 70 72 66 2e 65 65 5b } //100 - ]ue.prf.ee[
		$a_01_1 = {75 68 75 72 6f 73 77 48 20 78 68 71 75 68 78 71 4c 20 76 63 72 67 71 6c 43 } //100 uhuroswH xhquhxqL vcrgqlC
		$a_01_2 = {51 5a 55 5c 51 52 4c 56 55 48 59 58 51 48 55 55 5a 46 5c 56 43 52 47 51 4c 43 5c 58 49 52 56 52 55 46 4c 50 5c 48 55 44 43 58 49 52 56 } //20 QZU\QRLVUHYXQHUUZF\VCRGQLC\XIRVRUFLP\HUDCXIRV
		$a_01_3 = {70 68 78 76 62 56 5c 76 68 6c 66 6c 6f 72 53 5c 71 72 6c 76 75 68 59 78 71 68 75 75 7a 46 5c 76 63 72 67 71 6c 43 5c 78 69 72 76 72 75 66 6c 50 5c 68 75 64 63 78 69 72 56 5c } //20 phxvbV\vhlflorS\qrlvuhYxqhuuzF\vcrgqlC\xirvruflP\hudcxirV\
		$a_01_4 = {44 5a 4f 68 6f 65 64 71 48 } //20 DZOhoedqH
		$a_01_5 = {75 6a 50 6e 76 64 58 68 6f 65 64 76 6c 47 } //20 ujPnvdXhoedvlG
		$a_01_6 = {6f 6f 67 2e 30 35 4f 54 56 62 70 65 6c 6f 5c } //20 oog.05OTVbpelo\
		$a_01_7 = {75 68 79 75 68 56 5f 75 68 75 72 6f 73 77 48 20 78 68 71 75 68 78 71 4c } //20 uhyuhV_uhuroswH xhquhxqL
		$a_01_8 = {63 68 6c 59 20 78 66 68 6d 65 52 66 72 47 20 6f 6f 68 6b 56 } //20 chlY xfhmeRfrG oohkV
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20+(#a_01_7  & 1)*20+(#a_01_8  & 1)*20) >=220
 
}