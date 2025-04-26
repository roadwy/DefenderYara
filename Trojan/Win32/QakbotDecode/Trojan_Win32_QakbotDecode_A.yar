
rule Trojan_Win32_QakbotDecode_A{
	meta:
		description = "Trojan:Win32/QakbotDecode.A,SIGNATURE_TYPE_CMDHSTR_EXT,20 00 20 00 04 00 00 "
		
	strings :
		$a_81_0 = {20 2d 64 65 63 6f 64 65 20 } //10  -decode 
		$a_81_1 = {5c 6f 75 74 70 75 74 2e 74 78 74 } //10 \output.txt
		$a_81_2 = {2e 73 71 6c } //10 .sql
		$a_81_3 = {63 65 72 74 75 74 69 6c } //2 certutil
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*2) >=32
 
}