
rule Trojan_Win32_Emotet_EJ{
	meta:
		description = "Trojan:Win32/Emotet.EJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 39 00 65 00 78 00 70 00 6f 00 73 00 65 00 64 00 32 00 34 00 65 00 6e 00 67 00 69 00 6e 00 65 00 2e 00 31 00 33 00 35 00 45 00 32 00 } //01 00  e9exposed24engine.135E2
		$a_01_1 = {63 75 6d 73 68 6f 74 63 70 61 72 74 69 65 73 34 31 32 33 34 35 36 45 6e 67 6c 61 6e 64 2e 70 } //00 00  cumshotcparties4123456England.p
	condition:
		any of ($a_*)
 
}