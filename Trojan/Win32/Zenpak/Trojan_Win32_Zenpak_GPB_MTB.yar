
rule Trojan_Win32_Zenpak_GPB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 8b 75 90 01 01 32 1c 3e 8b 7d 90 01 01 88 1c 0f c7 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}