
rule Trojan_Win32_Zusy_EH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {3f 50 57 89 e7 81 c7 04 00 00 00 83 ef 04 87 3c 24 8b 24 24 89 04 24 89 2c 24 58 e9 0c e3 ff ff ff 34 24 5b 53 54 5b 81 c3 04 00 00 00 81 c3 04 00 00 00 87 1c 24 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Zusy_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 61 6d 72 68 47 37 49 4f 46 36 41 51 6c 34 6b 42 73 31 41 66 71 33 73 76 33 4e 71 78 47 47 67 3d } //1 HamrhG7IOF6AQl4kBs1Afq3sv3NqxGGg=
		$a_01_1 = {57 41 68 67 53 4a 6c 77 76 62 41 67 4c 51 72 44 71 79 6a 6c 4e 48 50 } //1 WAhgSJlwvbAgLQrDqyjlNHP
		$a_01_2 = {77 57 5a 45 45 72 52 42 59 61 6d 61 6c 6d 43 45 70 74 4f 67 71 79 4e } //1 wWZEErRBYamalmCEptOgqyN
		$a_01_3 = {6e 71 6a 69 54 76 42 67 6f 52 51 6e 46 4d 44 61 4b 78 58 76 58 43 54 } //1 nqjiTvBgoRQnFMDaKxXvXCT
		$a_01_4 = {44 6e 73 48 6f 73 74 6e 61 6d 65 54 6f 43 6f 6d 70 75 74 65 72 4e 61 6d 65 57 } //1 DnsHostnameToComputerNameW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}