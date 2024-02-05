
rule Trojan_BAT_Xmrig_AJMD_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.AJMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 08 9a 28 90 01 03 0a 0d 09 18 5d 2d 0e 07 08 09 1f 19 58 28 90 01 03 0a 9c 2b 0c 07 08 09 1f 0f 59 28 90 01 03 0a 9c 08 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}