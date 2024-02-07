
rule TrojanSpy_Win32_Bancos_UD{
	meta:
		description = "TrojanSpy:Win32/Bancos.UD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {3c 00 68 00 6b 00 3e 00 00 00 } //02 00 
		$a_01_1 = {64 00 78 00 6d 00 61 00 73 00 2e 00 73 00 79 00 73 00 00 00 } //01 00 
		$a_01_2 = {7b 00 66 00 36 00 7d 00 00 00 } //01 00 
		$a_01_3 = {77 73 63 6e 74 66 79 00 } //00 00  獷湣晴y
	condition:
		any of ($a_*)
 
}