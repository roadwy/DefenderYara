
rule Trojan_Win64_QQrob_RPY_MTB{
	meta:
		description = "Trojan:Win64/QQrob.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 8b c0 c7 44 24 20 04 00 00 00 33 d2 41 b9 00 10 00 00 48 8b ce ff 15 } //01 00 
		$a_01_1 = {76 61 6e 74 61 63 68 65 61 74 73 2e 72 69 70 } //00 00  vantacheats.rip
	condition:
		any of ($a_*)
 
}