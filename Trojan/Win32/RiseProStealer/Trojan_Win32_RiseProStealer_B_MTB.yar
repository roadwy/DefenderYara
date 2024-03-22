
rule Trojan_Win32_RiseProStealer_B_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 f3 31 03 5b 83 ec 90 09 17 00 53 55 68 90 01 04 5d 81 cd 90 01 04 81 c5 90 01 04 55 5b 5d 90 00 } //02 00 
		$a_01_1 = {5e 01 f2 01 1a 5a 68 } //00 00 
	condition:
		any of ($a_*)
 
}