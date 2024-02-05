
rule Trojan_BAT_Redline_NEK_MTB{
	meta:
		description = "Trojan:BAT/Redline.NEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 1e 00 00 0a 25 20 4c 04 00 00 20 ac 0d 00 00 6f 1f 00 00 0a 28 20 00 00 0a 72 59 00 00 70 28 0d 00 00 06 20 f4 01 00 00 20 ac 0d 00 00 6f 1f 00 00 0a 28 20 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}