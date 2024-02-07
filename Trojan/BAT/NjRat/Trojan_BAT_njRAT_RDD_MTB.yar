
rule Trojan_BAT_njRAT_RDD_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 07 02 07 91 08 1f 1f 5f 62 02 07 91 1e 08 59 1f 1f 5f 63 60 d2 9c 1a 0d } //01 00 
		$a_01_1 = {43 6f 6e 66 75 73 65 72 45 78 } //01 00  ConfuserEx
		$a_01_2 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}