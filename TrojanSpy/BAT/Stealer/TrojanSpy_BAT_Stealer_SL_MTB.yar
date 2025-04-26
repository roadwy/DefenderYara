
rule TrojanSpy_BAT_Stealer_SL_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 72 a5 00 00 70 6f 19 00 00 0a 6f 1a 00 00 0a 0d 09 08 6f 1b 00 00 0a 08 6f 0c 00 00 0a 0a dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}