
rule Trojan_O97M_Azorult_A_MSR{
	meta:
		description = "Trojan:O97M/Azorult.A!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 22 69 70 63 6f 6e 66 69 67 22 } //01 00  Shell "ipconfig"
		$a_00_1 = {22 53 22 20 26 20 22 6f 22 20 26 20 22 66 22 20 26 20 22 74 22 20 26 20 22 77 22 20 26 20 22 61 22 20 26 20 22 72 } //01 00  "S" & "o" & "f" & "t" & "w" & "a" & "r
		$a_00_2 = {52 65 67 57 72 69 74 65 } //00 00  RegWrite
	condition:
		any of ($a_*)
 
}