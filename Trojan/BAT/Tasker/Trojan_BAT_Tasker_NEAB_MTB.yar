
rule Trojan_BAT_Tasker_NEAB_MTB{
	meta:
		description = "Trojan:BAT/Tasker.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 30 00 00 0a 0a 06 72 64 01 00 70 6f 31 00 00 0a 06 72 74 01 00 70 28 0d 00 00 06 28 13 00 00 06 28 10 00 00 0a 6f 32 00 00 0a 06 17 6f 33 00 00 0a 06 16 6f 34 00 00 0a 06 28 35 00 00 0a 26 2a } //10
		$a_01_1 = {63 00 6c 00 69 00 70 00 70 00 65 00 72 00 2e 00 67 00 75 00 72 00 75 00 } //5 clipper.guru
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}