
rule Trojan_BAT_KillWin_SWS_MTB{
	meta:
		description = "Trojan:BAT/KillWin.SWS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 02 16 02 8e 69 6f 62 00 00 0a 09 6f 63 00 00 0a de 0a 09 2c 06 09 6f 39 00 00 0a dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}