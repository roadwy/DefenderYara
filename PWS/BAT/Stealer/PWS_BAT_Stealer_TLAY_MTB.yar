
rule PWS_BAT_Stealer_TLAY_MTB{
	meta:
		description = "PWS:BAT/Stealer.TLAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 8f 16 00 00 01 25 47 06 61 d2 52 11 06 17 58 13 06 11 06 07 8e 69 32 e5 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}