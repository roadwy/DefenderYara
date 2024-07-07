
rule Backdoor_Win32_Ofreayo_A{
	meta:
		description = "Backdoor:Win32/Ofreayo.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 0a 00 00 "
		
	strings :
		$a_03_0 = {8a 44 18 ff 04 80 88 45 fa 8d 45 90 01 01 8a 55 fb 32 55 fa e8 90 01 04 8b 55 90 01 01 8d 45 f4 e8 90 01 04 8b c7 e8 90 01 04 3b f0 7c b6 90 00 } //5
		$a_01_1 = {3c 64 6f 75 72 6c 3e } //1 <dourl>
		$a_01_2 = {3c 72 65 66 75 72 6c 31 3e } //1 <refurl1>
		$a_01_3 = {3c 73 61 79 66 61 31 3e } //1 <sayfa1>
		$a_01_4 = {3c 67 6f 72 75 6e 75 6d 3e } //1 <gorunum>
		$a_01_5 = {73 75 70 65 72 66 6c 6f 6f 64 } //1 superflood
		$a_01_6 = {68 74 74 70 66 6c 6f 6f 64 } //1 httpflood
		$a_01_7 = {64 6e 73 66 6c 6f 6f 64 } //1 dnsflood
		$a_01_8 = {73 70 72 65 61 64 } //1 spread
		$a_01_9 = {46 69 6c 65 20 77 61 73 20 44 6f 77 6e 6c 6f 61 64 65 64 20 26 20 45 78 65 63 75 74 65 64 21 } //1 File was Downloaded & Executed!
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=6
 
}