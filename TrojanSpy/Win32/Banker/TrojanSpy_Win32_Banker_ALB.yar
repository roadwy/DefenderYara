
rule TrojanSpy_Win32_Banker_ALB{
	meta:
		description = "TrojanSpy:Win32/Banker.ALB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 00 61 00 73 00 5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 5c 00 63 00 65 00 66 00 2e 00 67 00 70 00 63 00 } //1 mas\GbPlugin\cef.gpc
		$a_01_1 = {2f 00 73 00 61 00 76 00 65 00 69 00 6e 00 66 00 65 00 63 00 74 00 63 00 78 00 2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 63 00 6c 00 69 00 3d 00 } //1 /saveinfectcx.php?idcli=
		$a_01_2 = {69 00 6e 00 73 00 5c 00 69 00 6e 00 66 00 67 00 61 00 74 00 } //1 ins\infgat
		$a_01_3 = {26 00 67 00 62 00 43 00 58 00 3d 00 } //1 &gbCX=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}