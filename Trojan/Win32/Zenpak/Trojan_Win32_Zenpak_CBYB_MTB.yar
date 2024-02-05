
rule Trojan_Win32_Zenpak_CBYB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CBYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4a 42 83 ea 08 01 35 90 01 04 83 ea 07 83 f0 07 b8 03 00 00 00 8d 05 90 01 04 31 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}