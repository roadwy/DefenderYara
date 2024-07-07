
rule Trojan_Win32_Thogs_A{
	meta:
		description = "Trojan:Win32/Thogs.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5d f8 53 8b 0b 83 c3 04 85 c9 74 11 8b 03 83 c3 04 49 74 05 0f af 03 eb f5 8b c8 85 c9 0f 84 19 00 00 00 51 8b 03 85 c0 74 0b 53 50 e8 } //1
		$a_01_1 = {7c 32 31 31 7c 47 68 6f 73 74 7c 68 74 74 70 3a 2f 2f 79 79 66 6e 2e 33 33 32 32 2e 6f 72 67 7c 4c 6f 6f 6b 2e 50 48 50 7c 50 41 53 53 2e 50 48 50 } //1 |211|Ghost|http://yyfn.3322.org|Look.PHP|PASS.PHP
		$a_01_2 = {4d 79 48 69 00 21 2d 21 00 21 3d 21 00 21 2b 21 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}