
rule Trojan_Win32_Fodeweso{
	meta:
		description = "Trojan:Win32/Fodeweso,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 73 63 5f 70 72 6f 78 79 } //10 wsc_proxy
		$a_01_1 = {2f 72 75 6e 61 73 73 76 63 } //1 /runassvc
		$a_01_2 = {2f 72 70 63 73 65 72 76 65 72 } //1 /rpcserver
		$a_01_3 = {2f 77 73 63 5f 6e 61 6d 65 } //1 /wsc_name
		$a_01_4 = {2d 2d 64 69 73 61 62 6c 65 } //1 --disable
		$a_01_5 = {2d 2d 66 69 72 65 77 61 6c 6c } //1 --firewall
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}