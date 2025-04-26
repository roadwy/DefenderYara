
rule Trojan_Win32_Torrost_A{
	meta:
		description = "Trojan:Win32/Torrost.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 4c cc 00 00 ff d0 0f b7 c8 51 68 7f 00 00 01 e8 ?? ?? ff ff 8b f0 85 f6 0f 84 ?? 01 00 00 8b 15 ?? ?? ?? ?? 8b [0-05] 6a 00 6a 03 } //10
		$a_01_1 = {2e 6f 6e 69 6f 6e 2f 63 74 34 2e 70 68 70 } //1 .onion/ct4.php
		$a_01_2 = {53 6f 63 6b 73 50 6f 72 74 20 35 32 33 30 30 20 2d 2d 46 61 73 63 69 73 74 46 69 72 65 77 61 6c 6c 20 31 } //1 SocksPort 52300 --FascistFirewall 1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}