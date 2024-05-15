
rule Trojan_Win32_Ekstak_RN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {a7 64 00 6a 05 e8 90 01 01 fa 1f 00 8b 4c 24 00 33 c0 85 c9 0f 95 c0 59 90 00 } //01 00 
		$a_01_1 = {56 e8 2a 72 fb ff 8b f0 e9 } //00 00 
	condition:
		any of ($a_*)
 
}