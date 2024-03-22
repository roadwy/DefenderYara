
rule Trojan_Win32_Zenpak_CCHT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c2 02 8d 05 90 01 04 01 20 29 d0 83 e8 01 e8 90 01 04 42 89 d0 8d 05 90 01 04 01 38 8d 05 90 01 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}