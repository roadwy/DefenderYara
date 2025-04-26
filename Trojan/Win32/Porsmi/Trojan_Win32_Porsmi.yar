
rule Trojan_Win32_Porsmi{
	meta:
		description = "Trojan:Win32/Porsmi,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {80 38 ff 75 3c 8b 45 f8 80 78 01 fe 75 33 } //1
		$a_01_1 = {ff ff ff ff 07 00 00 00 55 50 5f 57 4f 52 4d 00 } //1
		$a_01_2 = {ff ff ff ff 05 00 00 00 63 69 73 68 75 00 } //1
		$a_01_3 = {ff ff ff ff 07 00 00 00 74 63 70 69 70 2e 6c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}