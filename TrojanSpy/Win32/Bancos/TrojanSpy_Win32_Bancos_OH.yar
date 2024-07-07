
rule TrojanSpy_Win32_Bancos_OH{
	meta:
		description = "TrojanSpy:Win32/Bancos.OH,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 00 00 00 72 62 2e 6d 6f 63 2e 61 73 65 72 70 6d 65 74 65 6e 6f 63 73 65 64 61 72 62 2f 2f 3a 73 70 74 74 68 00 00 00 ff ff ff ff 0b 00 00 00 43 65 72 74 69 66 69 63 61 64 6f 00 ff ff ff ff 12 00 00 00 7c 76 7c 7c 20 53 45 4e 48 41 20 7c 7c 76 7c 20 3e 3e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}