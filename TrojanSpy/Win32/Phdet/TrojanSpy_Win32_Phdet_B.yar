
rule TrojanSpy_Win32_Phdet_B{
	meta:
		description = "TrojanSpy:Win32/Phdet.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 9b 14 af ab 6a 01 e8 90 01 04 89 45 fc 8b 45 08 50 ff 55 fc 90 00 } //3
		$a_01_1 = {77 70 73 63 61 6e 00 } //1
		$a_01_2 = {66 61 69 6c 65 64 2e 20 4e 6f 74 20 61 20 53 79 73 74 65 6d 2e 0a 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}