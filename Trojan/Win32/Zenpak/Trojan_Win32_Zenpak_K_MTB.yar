
rule Trojan_Win32_Zenpak_K_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 0c 32 32 0c 1f 8b 5d 90 01 01 88 0c 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}