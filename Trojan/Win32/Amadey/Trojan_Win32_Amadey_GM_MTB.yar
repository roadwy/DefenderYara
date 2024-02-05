
rule Trojan_Win32_Amadey_GM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c1 c7 05 90 02 20 01 05 90 02 10 8b ff 8b 15 90 02 10 a1 90 02 10 89 02 90 00 } //01 00 
		$a_02_1 = {03 f0 8b 55 90 01 01 03 32 8b 45 90 01 01 89 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}