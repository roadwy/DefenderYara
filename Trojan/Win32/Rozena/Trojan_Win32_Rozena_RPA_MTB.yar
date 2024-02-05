
rule Trojan_Win32_Rozena_RPA_MTB{
	meta:
		description = "Trojan:Win32/Rozena.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f af c2 32 45 ef 89 c3 0f b6 4d ef 8b 55 f0 8b 45 0c 01 d0 8d 14 0b 88 10 8b 55 f0 8b 45 0c 01 d0 0f b6 10 0f b6 5d ef 8b 4d f0 8b 45 0c 01 c8 29 da 88 10 } //00 00 
	condition:
		any of ($a_*)
 
}