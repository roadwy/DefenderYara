
rule Trojan_Win32_Farfli_CM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 c2 8b 55 90 01 01 02 c8 8b 45 90 01 01 32 d9 00 18 90 00 } //01 00 
		$a_03_1 = {32 c2 02 c8 8b 45 90 01 01 32 d9 00 1c 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}