
rule Trojan_Win32_BlackMoon_NN_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 69 72 63 38 66 63 6c 34 72 72 38 39 34 66 32 75 72 35 90 01 04 37 65 30 37 37 37 35 90 01 04 6b 6e 71 36 38 77 37 38 6e 68 62 65 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}