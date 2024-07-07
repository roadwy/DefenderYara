
rule Backdoor_BAT_Bladabindi_BU_bit{
	meta:
		description = "Backdoor:BAT/Bladabindi.BU!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 4f 4b 00 4d 65 4d 00 } //1 伀K敍M
		$a_01_1 = {00 48 57 44 00 45 58 45 00 } //1
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 4e 4f 5f 4c 4f 56 49 4e 4f 5c } //1 C:\Users\NO_LOVINO\
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}