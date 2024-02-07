
rule Trojan_BAT_Snakekeylogger_WRL_MTB{
	meta:
		description = "Trojan:BAT/Snakekeylogger.WRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 25 17 59 } //01 00  ┇夗
		$a_03_1 = {fe 02 0c 08 2d df 28 90 01 03 06 00 16 2d e8 06 6f 90 01 03 0a 28 90 01 03 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}