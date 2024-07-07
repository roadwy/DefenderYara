
rule Trojan_Win32_PswStealer_C{
	meta:
		description = "Trojan:Win32/PswStealer.C,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffe8 03 ffffffd2 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //100 cmd.exe
		$a_00_1 = {20 00 70 00 61 00 73 00 73 00 } //100  pass
		$a_00_2 = {20 00 70 00 73 00 77 00 } //100  psw
		$a_00_3 = {63 00 6f 00 70 00 79 00 } //10 copy
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*10) >=210
 
}