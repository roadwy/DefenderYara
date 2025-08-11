
rule Backdoor_BAT_DCRat_BAA_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 05 02 16 02 8e 69 ?? ?? 00 00 0a 11 05 ?? ?? 00 00 0a 11 04 ?? ?? 00 00 0a 0b dd 1e 00 00 00 11 05 39 07 00 00 00 11 05 ?? ?? 00 00 0a dc 11 04 39 07 00 00 00 11 04 ?? ?? 00 00 0a dc 09 ?? ?? 00 00 0a dd 0d 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}