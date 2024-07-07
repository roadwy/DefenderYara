
rule Backdoor_Win64_Wainscot_A_dha{
	meta:
		description = "Backdoor:Win64/Wainscot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 3f 75 70 6c 6f 0f 85 e9 03 00 00 66 81 7f 90 01 01 61 64 66 90 90 0f 85 db 03 00 00 90 00 } //1
		$a_02_1 = {48 83 fe 09 0f 85 4d 01 00 00 49 ba 73 68 65 6c 6c 65 78 65 4c 39 17 0f 85 44 01 00 00 80 7f 90 01 01 63 0f 85 3a 01 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}