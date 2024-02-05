
rule Trojan_Win32_Zenpak_GPAB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {8b 7d e0 32 1c 37 8b 75 e4 88 } //00 00 
	condition:
		any of ($a_*)
 
}