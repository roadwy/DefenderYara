
rule Trojan_Win32_QBotCrypt_LK_MTB{
	meta:
		description = "Trojan:Win32/QBotCrypt.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {bb 00 00 00 00 90 02 05 53 ff 55 90 02 07 bb 00 30 00 00 53 3a c0 74 90 00 } //01 00 
		$a_01_1 = {54 69 6d 65 } //00 00  Time
	condition:
		any of ($a_*)
 
}