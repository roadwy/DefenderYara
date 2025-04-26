
rule Trojan_BAT_QuasarRAT_KAV_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 37 00 32 00 32 00 41 00 30 00 32 00 30 00 30 00 37 00 30 00 32 00 38 00 30 00 } //3 A722A020070280
		$a_01_1 = {41 00 32 00 35 00 37 00 32 00 33 00 35 00 31 00 36 00 30 00 30 00 37 00 } //3 A25723516007
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}