
rule Trojan_Win64_Ursnif_CCHT_MTB{
	meta:
		description = "Trojan:Win64/Ursnif.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 41 08 8b 4b 0c 8d 2c 11 48 03 ce 33 6c 24 20 33 6c 24 24 44 8d 45 0d } //00 00 
	condition:
		any of ($a_*)
 
}