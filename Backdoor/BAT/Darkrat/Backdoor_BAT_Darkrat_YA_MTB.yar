
rule Backdoor_BAT_Darkrat_YA_MTB{
	meta:
		description = "Backdoor:BAT/Darkrat.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 00 61 00 72 00 6b 00 72 00 61 00 74 00 66 00 75 00 64 00 } //1 darkratfud
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {26 00 6f 00 73 00 3d 00 } //1 &os=
		$a_01_3 = {26 00 70 00 63 00 3d 00 } //1 &pc=
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}