
rule Trojan_Win32_Zenpak_KAD_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 4d d4 8a 0c 0a 32 0c 1f 8b 5d e8 8b 55 d4 88 } //00 00 
	condition:
		any of ($a_*)
 
}