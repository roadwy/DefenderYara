
rule Trojan_Win32_QBot_RPZ_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 e8 3e ce f5 ff 6a 00 e8 37 ce f5 ff 6a 00 e8 30 ce f5 ff 6a 00 e8 29 ce f5 ff 6a 00 e8 22 ce f5 ff 6a 00 e8 1b ce f5 ff 6a 00 e8 14 ce f5 ff } //00 00 
	condition:
		any of ($a_*)
 
}