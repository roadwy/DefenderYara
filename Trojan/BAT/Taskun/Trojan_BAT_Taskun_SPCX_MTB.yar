
rule Trojan_BAT_Taskun_SPCX_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {07 11 08 11 0a 11 0b 61 11 0c 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}