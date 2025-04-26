
rule Backdoor_Win32_Bafruz_N{
	meta:
		description = "Backdoor:Win32/Bafruz.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {b8 3d 0d 00 00 e8 ?? ?? ?? ?? 68 60 ea 00 00 e8 ?? ?? ?? ?? 80 7b 0d 00 74 } //1
		$a_01_1 = {64 64 6f 73 5f 75 64 70 5f 6c 69 73 74 } //1 ddos_udp_list
		$a_01_2 = {75 64 70 2f 6b 6e 6f 63 6b 2e 70 68 70 3f 76 65 72 3d } //1 udp/knock.php?ver=
		$a_01_3 = {64 69 73 74 72 69 62 5f 73 65 72 76 2f 69 70 5f 6c 69 73 74 2e 70 68 70 } //1 distrib_serv/ip_list.php
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}