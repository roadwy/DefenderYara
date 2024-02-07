
rule TrojanSpy_AndroidOS_Cosha_A{
	meta:
		description = "TrojanSpy:AndroidOS/Cosha.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 52 65 63 69 65 76 65 41 43 } //01 00  IfRecieveAC
		$a_01_1 = {3e 3e 3e 3e 3e 3e 3e 3e 52 65 63 6f 72 64 65 72 54 61 73 6b 20 43 6f 6e 73 74 72 75 63 74 69 6f 6e 20 46 75 6e 63 } //01 00  >>>>>>>>RecorderTask Construction Func
		$a_01_2 = {3d 41 58 33 36 30 5f 53 65 72 76 3d } //01 00  =AX360_Serv=
		$a_01_3 = {63 6f 6f 73 68 61 72 65 2e 63 6f 6d 2f 63 61 72 65 75 2f 70 6f 73 69 74 69 6f 6e 72 65 63 6f 72 64 65 72 2e 61 73 6d 78 } //00 00  cooshare.com/careu/positionrecorder.asmx
	condition:
		any of ($a_*)
 
}