
rule HackTool_BAT_Grobo{
	meta:
		description = "HackTool:BAT/Grobo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {47 00 72 00 6f 00 77 00 42 00 6f 00 74 00 90 02 10 73 00 6b 00 79 00 70 00 65 00 90 00 } //01 00 
		$a_01_1 = {5f 73 70 61 6d 00 67 65 74 5f 73 70 61 6d 00 73 65 74 5f 73 70 61 6d 00 5f 73 65 6e 64 61 6c 6c } //00 00  獟慰m敧彴灳浡猀瑥獟慰m獟湥慤汬
	condition:
		any of ($a_*)
 
}