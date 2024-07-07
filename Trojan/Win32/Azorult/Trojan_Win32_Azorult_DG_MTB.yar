
rule Trojan_Win32_Azorult_DG_MTB{
	meta:
		description = "Trojan:Win32/Azorult.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_00_0 = {4d 4c 54 4f 4c 36 7a 61 41 59 4c 73 39 4d 39 5a 50 36 4b 62 56 37 75 67 39 49 44 61 50 49 38 65 } //3 MLTOL6zaAYLs9M9ZP6KbV7ug9IDaPI8e
		$a_81_1 = {52 65 67 69 73 74 65 72 41 75 74 6f 6d 61 74 69 6f 6e } //3 RegisterAutomation
		$a_81_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //3 CurrentVersion\Run
		$a_81_3 = {54 72 65 64 61 2e 64 6f 63 } //3 Treda.doc
		$a_81_4 = {5c 4d 61 63 72 6f 6d 65 64 69 61 5c } //3 \Macromedia\
		$a_81_5 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //3 LockResource
	condition:
		((#a_00_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}