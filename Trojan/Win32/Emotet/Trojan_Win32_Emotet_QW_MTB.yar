
rule Trojan_Win32_Emotet_QW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 4c 24 14 8b 44 24 10 33 d2 f7 f1 8b d8 8b 44 24 0c f7 f1 8b d3 eb 41 8b c8 8b 5c 24 14 8b 54 24 10 8b 44 24 0c d1 e9 d1 db d1 ea d1 d8 0b c9 75 f4 f7 f3 8b f0 f7 64 24 18 8b c8 8b 44 24 14 f7 e6 03 d1 } //10
		$a_81_1 = {43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c } //3 Control_RunDLL
		$a_81_2 = {68 71 75 6b 6e 69 76 73 6c 71 6b 62 } //3 hquknivslqkb
		$a_81_3 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //3 AppPolicyGetProcessTerminationMethod
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}