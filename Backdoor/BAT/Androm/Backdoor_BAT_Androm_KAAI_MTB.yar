
rule Backdoor_BAT_Androm_KAAI_MTB{
	meta:
		description = "Backdoor:BAT/Androm.KAAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 07 09 07 8e 69 5d 91 61 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}