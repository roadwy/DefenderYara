
rule Trojan_Win32_Socks5Systemz_ASO_MTB{
	meta:
		description = "Trojan:Win32/Socks5Systemz.ASO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b f0 c7 44 24 08 98 82 02 10 8d 44 24 08 50 8d 4c 24 40 } //1
		$a_01_1 = {8b f0 c7 44 24 0c 78 82 02 10 8d 44 24 0c 50 8d 4c 24 14 } //1
		$a_01_2 = {c7 44 24 48 24 00 00 00 89 74 24 4c c7 44 24 64 0f 00 00 00 c7 44 24 60 00 00 00 00 c6 44 24 50 00 c7 44 24 3c f4 81 02 10 8d 44 24 3c c7 44 24 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}