
rule Trojan_Win32_CoinMiner_QY_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QY!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 63 6f 6d 34 2e 7b 32 34 31 64 37 63 39 36 2d 66 38 62 66 2d 34 66 38 35 2d 62 30 31 66 2d 65 32 62 30 34 33 33 34 31 61 34 62 7d } //1 windows\system\com4.{241d7c96-f8bf-4f85-b01f-e2b043341a4b}
		$a_01_1 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 svchost.exe -k netsvcs
		$a_01_2 = {6d 69 6e 65 72 67 61 74 65 } //1 minergate
		$a_01_3 = {40 67 6d 61 69 6c 2e 63 6f 6d } //1 @gmail.com
		$a_01_4 = {43 50 55 20 6c 6f 61 64 } //1 CPU load
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}