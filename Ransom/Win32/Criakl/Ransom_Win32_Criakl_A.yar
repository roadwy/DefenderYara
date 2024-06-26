
rule Ransom_Win32_Criakl_A{
	meta:
		description = "Ransom:Win32/Criakl.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {7b 43 52 59 50 54 45 4e 44 42 4c 41 43 4b 44 43 7d } //01 00  {CRYPTENDBLACKDC}
		$a_01_1 = {7b 43 52 59 50 54 46 55 4c 4c 45 4e 44 } //01 00  {CRYPTFULLEND
		$a_01_2 = {7b 43 52 59 50 54 53 54 41 52 54 44 41 54 41 7d } //01 00  {CRYPTSTARTDATA}
		$a_00_3 = {6e 6f 74 74 68 69 73 6f 70 65 72 61 74 69 6f 6e 69 73 61 79 } //01 00  notthisoperationisay
		$a_00_4 = {3a 2a 2e 6d 64 66 3a 2a 2e 78 6c 73 3a 2a 2e 44 54 3a } //01 00  :*.mdf:*.xls:*.DT:
		$a_02_5 = {7b 4d 59 49 44 7d 90 02 10 7b 4d 59 4d 41 49 4c 7d 90 00 } //01 00 
		$a_00_6 = {2a 2e 70 70 74 78 7c 7c 7c 7b 7d 7c 7c 7c 30 30 30 } //00 00  *.pptx|||{}|||000
		$a_00_7 = {80 10 00 } //00 e0 
	condition:
		any of ($a_*)
 
}