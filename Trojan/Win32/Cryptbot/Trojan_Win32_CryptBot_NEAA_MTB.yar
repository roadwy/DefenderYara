
rule Trojan_Win32_CryptBot_NEAA_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 75 08 8a 0c 1a 30 0c 3e 46 81 fe 90 01 02 00 00 72 ea 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}