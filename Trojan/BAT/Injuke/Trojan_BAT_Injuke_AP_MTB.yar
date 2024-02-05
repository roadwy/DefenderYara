
rule Trojan_BAT_Injuke_AP_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 08 18 5b 02 08 18 6f 14 00 00 0a 1f 10 28 15 00 00 0a 9c 08 18 58 0c 08 06 32 } //02 00 
		$a_01_1 = {cd ef b9 ef ca ef bf ef b8 ef be ef bd ef c9 ef cc ef b8 ef be ef cf ef c9 ef cc ef ce ef be ef c5 ef b9 ef cb ef c5 ef c8 ef ce ef c5 ef c9 } //00 00 
	condition:
		any of ($a_*)
 
}