
rule TrojanSpy_Win32_Broler_G_dha{
	meta:
		description = "TrojanSpy:Win32/Broler.G!dha,SIGNATURE_TYPE_PEHSTR,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 6f 6e 67 66 65 69 79 65 2e 63 6f 6d } //5 http://www.longfeiye.com
		$a_01_1 = {68 74 74 70 3a 2f 2f 32 37 2e 32 35 35 2e 39 30 2e 31 35 38 2f 54 65 72 6d 69 6e 46 6f 6c 64 2f 6c 64 73 6a 72 2e 70 68 70 } //5 http://27.255.90.158/TerminFold/ldsjr.php
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 54 72 65 6e 64 4d 69 63 72 6f 5c 41 4d 53 50 } //1 SOFTWARE\TrendMicro\AMSP
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 33 36 30 53 61 66 65 5c 4c 69 76 65 75 70 } //1 SOFTWARE\360Safe\Liveup
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}