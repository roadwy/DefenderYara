
rule Backdoor_Win32_Teldoor_C{
	meta:
		description = "Backdoor:Win32/Teldoor.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 6c 6e 74 61 64 6d 6e 20 63 6f 6e 66 69 67 20 70 6f 72 74 3d 39 37 32 20 73 65 63 3d 2d 4e 54 4c 4d } //1 tlntadmn config port=972 sec=-NTLM
		$a_01_1 = {6e 65 74 20 73 74 61 72 74 20 54 65 6c 6e 65 74 } //1 net start Telnet
		$a_01_2 = {73 63 20 63 6f 6e 66 69 67 20 74 6c 6e 74 73 76 72 20 73 74 61 72 74 3d 20 61 75 74 6f } //1 sc config tlntsvr start= auto
		$a_01_3 = {53 55 50 50 4f 52 54 5f 33 38 38 39 34 35 61 30 20 2f 64 65 6c } //1 SUPPORT_388945a0 /del
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}