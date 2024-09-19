
rule Backdoor_BAT_NanoBot_SM_MTB{
	meta:
		description = "Backdoor:BAT/NanoBot.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {19 2c 0d 2b 0d 72 a5 00 00 70 2b 0d 2b 12 2b 17 de 1b 73 55 00 00 0a 2b ec 28 56 00 00 0a 2b ec 6f 57 00 00 0a 2b e7 0a 2b e6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}