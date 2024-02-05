
rule Trojan_BAT_Dnoper_CXRJK_MTB{
	meta:
		description = "Trojan:BAT/Dnoper.CXRJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 28 1e 00 00 0a 0a 1f 1a 28 1f 00 00 0a 72 90 01 01 d3 07 70 28 1d 00 00 0a 0c 08 06 28 20 00 00 0a 72 90 01 01 d3 07 70 72 90 01 01 d3 07 70 08 72 90 01 01 d3 07 70 28 21 00 00 0a 28 22 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}