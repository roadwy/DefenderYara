
rule Trojan_Win32_Vundo_QF{
	meta:
		description = "Trojan:Win32/Vundo.QF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 00 6d 00 7a 00 63 00 64 00 6c 00 6b 00 78 00 5f 00 73 00 6a 00 6b 00 6c 00 6d 00 64 00 65 00 } //2 vmzcdlkx_sjklmde
		$a_01_1 = {39 00 33 00 6a 00 64 00 73 00 6c 00 65 00 4a 00 64 00 6e 00 73 00 6b 00 6c 00 3a 00 } //2 93jdsleJdnskl:
		$a_01_2 = {ff ff 00 45 00 00 7d } //1
		$a_01_3 = {ff ff a0 86 01 00 0f 8d } //1
		$a_01_4 = {ff ff 90 d0 03 00 0f 87 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}