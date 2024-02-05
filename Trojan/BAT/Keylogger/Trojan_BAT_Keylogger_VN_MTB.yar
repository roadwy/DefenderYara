
rule Trojan_BAT_Keylogger_VN_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 0c 08 6f 90 01 03 0a 26 16 0d 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}