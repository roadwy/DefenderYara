
rule Trojan_BAT_Tasker_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Tasker.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 14 0b 06 8e 69 1a 58 7e 01 00 00 04 8e 69 30 36 16 0d 2b 19 06 09 8f 0e 00 00 01 25 47 7e 01 00 00 04 09 1a 58 91 5a d2 52 09 17 58 0d 09 06 8e 69 32 e1 06 28 1a 00 00 0a 0c 28 1b 00 00 0a } //10
		$a_01_1 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //2 Confuser.Core 1.6.0+447341964f
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}