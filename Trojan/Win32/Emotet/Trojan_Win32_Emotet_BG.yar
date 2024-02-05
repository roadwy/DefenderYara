
rule Trojan_Win32_Emotet_BG{
	meta:
		description = "Trojan:Win32/Emotet.BG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 72 51 55 46 6d 47 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}