
rule Trojan_Win32_Qhost_FH{
	meta:
		description = "Trojan:Win32/Qhost.FH,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 2e 73 79 73 } //02 00  :\WINDOWS\system32\drivers\etc\hosts.sys
		$a_01_1 = {39 31 2e 32 32 30 2e 30 2e 33 38 } //01 00  91.220.0.38
		$a_01_2 = {79 61 6e 64 65 78 2e 72 75 } //01 00  yandex.ru
		$a_01_3 = {67 6f 6f 67 6c 65 2e 63 6f 6d } //01 00  google.com
		$a_01_4 = {76 6b 6f 6e 74 61 6b 74 65 2e 72 75 } //01 00  vkontakte.ru
		$a_01_5 = {39 31 2e 32 32 33 2e 38 39 2e 31 30 31 } //01 00  91.223.89.101
		$a_01_6 = {39 33 2e 37 33 2e 31 34 38 2e 31 37 } //01 00  93.73.148.17
		$a_01_7 = {39 37 2e 32 35 33 2e 31 39 2e 39 } //00 00  97.253.19.9
	condition:
		any of ($a_*)
 
}