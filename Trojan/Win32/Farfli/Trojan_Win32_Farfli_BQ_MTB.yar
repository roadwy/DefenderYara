
rule Trojan_Win32_Farfli_BQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8a 1c 11 80 f3 36 88 1c 11 8b 55 fc 8a 1c 11 80 c3 12 88 1c 11 8b 55 fc 8a 1c 11 80 c3 bc 88 1c 11 8b 55 fc 8a 1c 11 80 f3 18 88 1c 11 41 3b c8 7c } //00 00 
	condition:
		any of ($a_*)
 
}