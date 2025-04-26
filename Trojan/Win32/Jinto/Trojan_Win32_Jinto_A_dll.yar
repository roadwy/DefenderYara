
rule Trojan_Win32_Jinto_A_dll{
	meta:
		description = "Trojan:Win32/Jinto.A!dll,SIGNATURE_TYPE_PEHSTR,20 00 1f 00 07 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 63 6f 72 65 63 6f 6e 66 69 67 00 00 00 67 65 74 70 6c 75 67 69 6e 63 6f 6e 66 69 67 } //10
		$a_01_1 = {25 73 5f 53 74 61 72 74 5f 25 63 5f 75 70 } //10 %s_Start_%c_up
		$a_01_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //10 SYSTEM\CurrentControlSet\Services\%s
		$a_01_3 = {61 63 74 3d 75 70 64 61 74 65 26 62 6f 74 5f 69 64 3d 25 73 26 62 69 64 3d 25 73 26 6f 73 3d 25 64 26 76 65 72 73 69 6f 6e 3d 25 64 26 73 70 3d 25 64 26 73 6f 63 6b 73 3d 25 64 } //1 act=update&bot_id=%s&bid=%s&os=%d&version=%d&sp=%d&socks=%d
		$a_01_4 = {61 63 74 3d 67 65 74 70 6c 75 67 69 6e 26 62 6f 74 5f 69 64 3d 25 73 26 70 6c 75 67 69 6e 5f 6e 61 6d 65 3d 25 73 } //1 act=getplugin&bot_id=%s&plugin_name=%s
		$a_01_5 = {61 63 74 3d 25 73 26 62 6f 74 5f 69 64 3d 25 73 26 70 6c 75 67 69 6e 5f 6e 61 6d 65 3d 25 73 } //1 act=%s&bot_id=%s&plugin_name=%s
		$a_01_6 = {61 63 74 3d 6f 75 74 26 62 6f 74 5f 69 64 3d 25 73 26 64 61 74 61 5f 74 79 70 65 3d 25 64 } //1 act=out&bot_id=%s&data_type=%d
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=31
 
}