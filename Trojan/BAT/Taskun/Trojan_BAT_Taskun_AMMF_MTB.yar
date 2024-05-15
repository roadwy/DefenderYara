
rule Trojan_BAT_Taskun_AMMF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 91 13 90 02 1e 59 20 00 01 00 00 58 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}