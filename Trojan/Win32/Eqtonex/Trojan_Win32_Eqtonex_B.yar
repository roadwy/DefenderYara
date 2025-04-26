
rule Trojan_Win32_Eqtonex_B{
	meta:
		description = "Trojan:Win32/Eqtonex.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 c9 0d 66 19 00 81 c1 5f f3 6e 3c 8b f1 c1 ee 10 66 81 ce 00 80 66 31 34 42 40 3b 45 10 } //2
		$a_01_1 = {64 6c 6c 5f 70 00 64 6c 6c 5f 75 00 } //2 汤彬p汤彬u
		$a_01_2 = {5c 00 3f 00 3f 00 5c 00 25 00 73 00 5c 00 25 00 73 00 } //1 \??\%s\%s
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}