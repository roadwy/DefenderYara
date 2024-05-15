
rule Trojan_Win32_Zenpak_NA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {30 cd 8b 55 e8 88 2c 1a 81 c3 90 01 04 8b 55 f0 39 d3 89 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}