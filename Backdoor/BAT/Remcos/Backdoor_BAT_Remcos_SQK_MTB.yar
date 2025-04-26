
rule Backdoor_BAT_Remcos_SQK_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 0d 1f 0d 5a 11 08 19 62 61 58 13 08 00 11 0c 17 58 13 0c 11 0c 11 0b } //2
		$a_81_1 = {41 74 74 65 6e 64 61 6e 63 65 54 72 61 63 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 AttendanceTracker.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}