
rule Trojan_Win32_Zusy_MBHO_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 75 69 79 75 6d 74 79 6e 72 2e 64 6c 6c 00 75 69 79 75 74 79 64 72 00 75 69 66 75 6d 74 64 79 72 } //00 00 
	condition:
		any of ($a_*)
 
}