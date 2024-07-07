
rule Trojan_Win32_Folyris_A{
	meta:
		description = "Trojan:Win32/Folyris.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 69 64 3a 25 73 7c 74 61 73 6b 69 64 3a 25 69 } //1 uid:%s|taskid:%i
		$a_01_1 = {c7 03 74 72 75 65 c6 43 04 00 eb 0c c7 03 66 61 6c 73 66 c7 43 04 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}