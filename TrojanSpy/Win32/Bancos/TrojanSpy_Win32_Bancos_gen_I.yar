
rule TrojanSpy_Win32_Bancos_gen_I{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 63 68 61 76 65 00 } //1
		$a_00_1 = {06 13 73 6c 36 35 62 6c 61 63 6b 40 67 6d 61 69 6c 2e 63 6f 6d 00 } //1
		$a_03_2 = {bf 01 00 00 00 8b 85 90 01 01 fe ff ff 33 db 8a 5c 38 ff 33 9d 90 01 01 fe ff ff 3b 9d 90 01 01 fe ff ff 7f 0e 81 c3 ff 00 00 00 2b 9d 90 01 01 fe ff ff eb 06 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}