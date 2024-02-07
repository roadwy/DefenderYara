
rule Trojan_Win32_Agent_AFZ{
	meta:
		description = "Trojan:Win32/Agent.AFZ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 65 6e 63 5c 41 44 4f 44 42 2e 64 6c 6c } //01 00  cenc\ADODB.dll
		$a_01_1 = {68 6f 63 74 5f 75 70 64 61 74 61 2e 65 78 65 } //01 00  hoct_updata.exe
		$a_01_2 = {62 61 6f 2e 6c 79 6c 77 63 } //00 00  bao.lylwc
	condition:
		any of ($a_*)
 
}