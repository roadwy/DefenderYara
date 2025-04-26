
rule Trojan_Win32_Coroxy_YBN_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.YBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6f 63 6b 73 35 } //1 socks5
		$a_01_1 = {8a 04 3b 30 06 46 43 } //10
		$a_01_2 = {50 68 7e 66 04 80 ff 75 fc e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=12
 
}