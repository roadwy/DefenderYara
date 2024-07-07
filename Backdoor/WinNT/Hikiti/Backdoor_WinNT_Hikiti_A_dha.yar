
rule Backdoor_WinNT_Hikiti_A_dha{
	meta:
		description = "Backdoor:WinNT/Hikiti.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 6d 61 67 65 6e 61 6d 65 20 66 6f 75 6e 64 20 61 74 3a 25 73 } //1 imagename found at:%s
		$a_00_1 = {68 69 64 65 2d 2d 2d 70 6f 72 74 20 3d 20 25 64 } //2 hide---port = %d
		$a_02_2 = {2d 2d 2d 68 69 64 65 90 02 40 2e 64 61 74 61 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2) >=5
 
}