
rule Trojan_Win32_Coinminer_QF{
	meta:
		description = "Trojan:Win32/Coinminer.QF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {aa 33 c0 80 74 05 e0 aa 40 83 f8 0d 72 } //1
		$a_01_1 = {47 00 69 00 6d 00 6c 00 69 00 2e 00 6a 00 6f 00 62 00 } //1 Gimli.job
		$a_01_2 = {2d 00 61 00 20 00 63 00 72 00 79 00 70 00 74 00 6f 00 6e 00 69 00 67 00 68 00 74 00 20 00 2d 00 6f 00 20 00 73 00 74 00 72 00 61 00 74 00 75 00 6d 00 2b 00 74 00 63 00 70 00 3a 00 2f 00 2f 00 } //1 -a cryptonight -o stratum+tcp://
		$a_01_3 = {61 6e 74 69 76 69 72 75 73 20 66 6f 75 6e 64 } //1 antivirus found
		$a_01_4 = {2f 00 63 00 20 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 70 00 69 00 64 00 20 00 } //1 /c taskkill /f /pid 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}