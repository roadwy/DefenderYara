
rule Trojan_BAT_Taskun_SDFB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SDFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {07 11 13 07 11 13 91 11 16 61 11 15 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}