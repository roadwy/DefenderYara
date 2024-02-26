
rule Trojan_BAT_Taskun_SPCC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c 00 11 06 17 58 13 06 } //00 00 
	condition:
		any of ($a_*)
 
}