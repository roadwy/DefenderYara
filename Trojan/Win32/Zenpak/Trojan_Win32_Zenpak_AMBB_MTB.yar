
rule Trojan_Win32_Zenpak_AMBB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {32 0c 32 8b 55 90 01 01 88 0c 32 8b 4d 90 01 01 39 cf 89 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}