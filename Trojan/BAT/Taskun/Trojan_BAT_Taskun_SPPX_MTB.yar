
rule Trojan_BAT_Taskun_SPPX_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {06 09 6a 5d d4 11 90 01 01 28 90 01 03 0a 9c 06 17 6a 58 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}