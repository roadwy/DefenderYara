
rule Trojan_Win32_DorkBot_DU{
	meta:
		description = "Trojan:Win32/DorkBot.DU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 57 51 8b 74 24 14 8b 7c 24 10 8b 4c 24 18 f3 a4 59 5f 5e c2 0c 00 cc cc } //00 00 
	condition:
		any of ($a_*)
 
}