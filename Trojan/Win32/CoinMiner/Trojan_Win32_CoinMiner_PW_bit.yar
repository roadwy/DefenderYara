
rule Trojan_Win32_CoinMiner_PW_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.PW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6f 77 6e 30 31 31 36 2e 69 6e 66 6f } //1 .down0116.info
		$a_01_1 = {5b 25 64 5d 20 25 73 20 6b 69 6c 6c 20 70 72 6f 63 3a 20 25 73 2c 66 69 6c 65 3a 20 25 73 } //1 [%d] %s kill proc: %s,file: %s
		$a_01_2 = {64 65 6c 20 2f 46 20 2f 41 52 48 53 20 22 25 73 22 } //1 del /F /ARHS "%s"
		$a_01_3 = {2f 43 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 36 20 26 20 74 61 73 6b 6b 69 6c 6c 20 2d 66 20 2f 69 6d 20 63 6f 6e 69 6d 65 2e 65 78 65 20 2f 69 6d } //1 /C ping 127.0.0.1 -n 6 & taskkill -f /im conime.exe /im
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_CoinMiner_PW_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.PW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 25 73 20 2d 75 20 25 73 } //1 -o stratum+tcp://%s -u %s
		$a_01_1 = {3a 2f 2f 25 73 3a 38 38 38 38 2f 6d 64 35 2e 74 78 74 } //1 ://%s:8888/md5.txt
		$a_01_2 = {3a 2f 2f 25 73 3a 38 38 38 38 2f 78 6d 72 6f 6b 2e 74 78 74 } //1 ://%s:8888/xmrok.txt
		$a_01_3 = {70 75 62 79 75 6e 2e 63 6f 6d 2f 64 79 6e 64 6e 73 2f 67 65 74 69 70 } //1 pubyun.com/dyndns/getip
		$a_01_4 = {61 63 63 65 73 73 20 73 69 6e 61 20 62 6c 6f 67 20 6f 6b 2c 20 68 6f 73 74 3a 20 25 73 } //1 access sina blog ok, host: %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}