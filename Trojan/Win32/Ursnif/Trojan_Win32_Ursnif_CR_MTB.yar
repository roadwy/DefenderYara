
rule Trojan_Win32_Ursnif_CR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.CR!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2b 75 dc 03 c6 89 01 8b f7 83 c1 04 eb 07 c7 45 f4 01 00 00 00 ff 4d f4 } //00 00 
	condition:
		any of ($a_*)
 
}