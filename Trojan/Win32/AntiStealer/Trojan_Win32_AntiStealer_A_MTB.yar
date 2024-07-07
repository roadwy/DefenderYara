
rule Trojan_Win32_AntiStealer_A_MTB{
	meta:
		description = "Trojan:Win32/AntiStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 6e 00 74 00 69 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 } //2 AntiStealer
		$a_01_1 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //2 GET %s HTTP/1.1
		$a_01_2 = {48 6f 73 74 3a 20 25 73 } //2 Host: %s
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 25 73 } //2 User-Agent: %s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}