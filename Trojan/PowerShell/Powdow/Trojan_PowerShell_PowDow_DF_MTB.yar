
rule Trojan_PowerShell_PowDow_DF_MTB{
	meta:
		description = "Trojan:PowerShell/PowDow.DF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 73 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 } //10 curl -s http:/
		$a_00_1 = {2d 00 6f 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 } //1 -o %temp%
		$a_00_2 = {3e 00 6e 00 75 00 6c 00 20 00 26 00 26 00 } //10 >nul &&
		$a_00_3 = {3a 00 56 00 42 00 53 00 63 00 72 00 69 00 70 00 74 00 } //10 :VBScript
		$a_00_4 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 } //1 AppData\Local\Temp
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*1) >=31
 
}