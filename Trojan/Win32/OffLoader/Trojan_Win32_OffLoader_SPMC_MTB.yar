
rule Trojan_Win32_OffLoader_SPMC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 00 6f 00 6c 00 6c 00 73 00 68 00 61 00 6e 00 64 00 73 00 2e 00 69 00 63 00 75 00 2f 00 61 00 72 00 70 00 6b 00 2e 00 70 00 68 00 70 00 } //02 00  dollshands.icu/arpk.php
		$a_01_1 = {73 00 68 00 61 00 6b 00 65 00 73 00 6c 00 65 00 65 00 70 00 2e 00 62 00 6f 00 6e 00 64 00 2f 00 61 00 72 00 70 00 74 00 2e 00 70 00 68 00 70 00 } //00 00  shakesleep.bond/arpt.php
	condition:
		any of ($a_*)
 
}