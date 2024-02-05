
rule Trojan_Win32_Bunitucrypt_RTC_MTB{
	meta:
		description = "Trojan:Win32/Bunitucrypt.RTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 02 33 c0 a3 90 01 04 a1 90 01 04 83 c0 04 01 05 90 01 04 a1 90 01 04 83 c0 04 90 00 } //01 00 
		$a_03_1 = {2d 00 10 00 00 90 02 0a 83 90 02 05 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}