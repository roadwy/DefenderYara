
rule TrojanSpy_Win32_Bancos_AKF{
	meta:
		description = "TrojanSpy:Win32/Bancos.AKF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 } //3
		$a_01_1 = {72 65 6d 6f 76 65 64 6f 72 } //1 removedor
		$a_01_2 = {49 43 45 46 49 52 45 } //1 ICEFIRE
		$a_01_3 = {46 4f 58 54 45 4b } //1 FOXTEK
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}