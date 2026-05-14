
rule Backdoor_BAT_SneakyGrunt_B_dha{
	meta:
		description = "Backdoor:BAT/SneakyGrunt.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 61 6d 65 48 61 73 68 65 64 } //1 nameHashed
		$a_01_1 = {63 00 61 00 2e 00 65 00 78 00 65 00 } //1 ca.exe
		$a_01_2 = {2f 00 64 00 65 00 6c 00 65 00 74 00 65 00 2f 00 70 00 65 00 72 00 6d 00 61 00 6e 00 65 00 6e 00 74 00 } //1 /delete/permanent
		$a_01_3 = {75 70 6c 6f 61 64 4b 65 79 } //1 uploadKey
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}