
rule Trojan_Win32_FakeAlert_NF_MTB{
	meta:
		description = "Trojan:Win32/FakeAlert.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {a0 38 68 41 00 22 05 12 68 41 00 a2 10 68 41 00 8b 44 24 08 a3 54 68 41 00 2a 05 13 68 41 00 a2 15 68 41 00 0f be 05 11 68 41 00 } //2
		$a_01_1 = {ff 75 0c 01 05 50 68 41 00 8b 4d f8 8d 04 1e 6a 03 50 e8 04 fc ff ff 66 c7 05 20 68 41 00 01 00 83 c6 03 } //1
		$a_01_2 = {47 65 74 43 61 70 74 75 72 65 } //1 GetCapture
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}