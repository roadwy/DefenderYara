
rule Trojan_Win32_Lazy_WEE_MTB{
	meta:
		description = "Trojan:Win32/Lazy.WEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 04 0b 8d 4d 90 01 01 e8 90 01 04 8b 55 90 01 01 43 3b 9d 90 01 04 89 5d 90 01 01 8b 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}