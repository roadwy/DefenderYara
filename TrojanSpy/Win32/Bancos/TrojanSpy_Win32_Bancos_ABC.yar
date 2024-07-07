
rule TrojanSpy_Win32_Bancos_ABC{
	meta:
		description = "TrojanSpy:Win32/Bancos.ABC,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 61 73 43 6f 6d 6d 6f 6e 5f 76 44 65 43 72 69 70 74 } //3 basCommon_vDeCript
		$a_01_1 = {66 72 6d 4d 6f 74 68 65 72 46 75 63 6b 65 72 } //3 frmMotherFucker
		$a_01_2 = {62 61 73 43 6f 6d 6d 6f 6e 48 61 72 64 44 69 73 6b 52 65 61 6c 53 65 72 69 61 6c 43 6c 61 73 73 } //2 basCommonHardDiskRealSerialClass
		$a_01_3 = {79 00 79 00 33 00 31 00 33 00 39 00 36 00 } //2 yy31396
		$a_01_4 = {5c 00 5c 00 2e 00 5c 00 53 00 4d 00 41 00 52 00 54 00 56 00 53 00 44 00 } //1 \\.\SMARTVSD
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=8
 
}