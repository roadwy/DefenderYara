
rule Backdoor_BAT_Crysan_FVAA_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.FVAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0b 16 0c 17 0d 2b 14 08 09 19 2c 0d 16 2d 0e 58 16 2d 09 1a 2c b4 0c 09 17 58 0d 09 02 31 e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}