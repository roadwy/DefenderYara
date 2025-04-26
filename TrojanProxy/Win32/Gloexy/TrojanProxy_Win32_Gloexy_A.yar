
rule TrojanProxy_Win32_Gloexy_A{
	meta:
		description = "TrojanProxy:Win32/Gloexy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 6f 63 6b 73 31 31 } //1 socks11
		$a_01_1 = {68 00 30 00 00 2b c2 03 c6 33 d2 f7 f6 8d 4c 81 06 51 53 89 4d f8 ff 15 } //1
		$a_03_2 = {3b c6 0f 84 ?? ?? ?? ?? 83 7d bc 04 c7 45 fc 00 01 00 84 75 07 c7 45 fc 00 01 80 84 53 56 ff 75 fc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}