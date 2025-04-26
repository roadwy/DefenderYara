
rule Trojan_BAT_ClipBanker_PSSX_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.PSSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f ac 00 00 0a 06 07 6f ad 00 00 0a 17 73 5d 00 00 0a 25 02 16 02 8e 69 6f ae 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}