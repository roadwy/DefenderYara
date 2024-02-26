
rule Trojan_Win32_LummaStealer_CCHC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 50 6a 00 53 ff 15 } //01 00 
		$a_01_1 = {50 ff 75 f8 ff 75 b0 57 53 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}