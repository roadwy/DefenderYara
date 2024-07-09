
rule Trojan_Win32_CoinMiner_RD_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.RD!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 52 75 6e 41 70 70 2e 76 62 73 } //1 AutoRunApp.vbs
		$a_01_1 = {2f 6e 6f 6c 6f 67 6f 20 25 74 6d 70 25 2f 64 65 6c 61 79 2e 76 62 73 } //1 /nologo %tmp%/delay.vbs
		$a_03_2 = {2d 2d 64 6f 6e 61 74 65 2d 6c 65 76 65 6c [0-10] 2d 2d 6d 61 78 2d 63 70 75 2d 75 73 61 67 65 [0-10] 2d 6f [0-50] 2d 75 [0-50] 2d 70 [0-50] 2d 6b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}