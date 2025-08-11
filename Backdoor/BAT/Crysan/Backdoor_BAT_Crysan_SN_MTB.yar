
rule Backdoor_BAT_Crysan_SN_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 6f 0a 00 00 0a 0d 09 02 16 02 8e 69 6f 0b 00 00 0a 13 04 dd 1a 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}