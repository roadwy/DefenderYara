
rule Trojan_Win32_Qbot_AP_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {00 58 35 35 35 00 } //1 堀㔵5
		$a_01_1 = {00 54 6d 65 6d 6d 6f 76 65 5f 73 00 } //1 吀敭浭癯彥s
		$a_01_2 = {00 54 63 73 74 6f 6d 62 73 5f 73 00 } //1 吀獣潴扭彳s
		$a_01_3 = {00 54 63 73 6e 63 70 79 5f 73 00 } //1
		$a_01_4 = {00 54 66 77 70 72 69 6e 74 66 5f 73 00 } //1
		$a_01_5 = {00 54 6d 70 6e 61 6d 5f 73 00 } //1 吀灭慮彭s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}