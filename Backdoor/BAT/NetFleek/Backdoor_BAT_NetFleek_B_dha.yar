
rule Backdoor_BAT_NetFleek_B_dha{
	meta:
		description = "Backdoor:BAT/NetFleek.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {46 69 72 6d 61 63 68 41 67 65 6e 74 } //1 FirmachAgent
		$a_01_1 = {74 00 61 00 73 00 6b 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 } //1 task/upload
		$a_01_2 = {74 00 61 00 73 00 6b 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //1 task/download
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}