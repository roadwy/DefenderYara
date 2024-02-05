
rule Trojan_Win32_Emotet_DF{
	meta:
		description = "Trojan:Win32/Emotet.DF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 79 49 52 42 74 64 46 6c 4d 73 49 } //00 00 
	condition:
		any of ($a_*)
 
}