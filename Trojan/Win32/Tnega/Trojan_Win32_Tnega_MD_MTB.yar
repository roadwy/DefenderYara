
rule Trojan_Win32_Tnega_MD_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 1e 00 88 0a 05 6b 67 1a 45 12 3a 87 ac 17 5a 6b } //00 00 
	condition:
		any of ($a_*)
 
}