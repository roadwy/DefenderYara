
rule Trojan_Win32_Lazy_MBJE_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MBJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 c0 66 ad 85 c0 74 18 01 c3 66 ad 85 c0 74 10 89 c1 51 53 57 e8 0b 00 00 00 01 cb 89 c7 eb e0 } //01 00 
		$a_01_1 = {62 79 65 7a 00 69 79 71 72 79 78 6e 77 6c 62 6c 7a 00 69 78 70 } //00 00 
	condition:
		any of ($a_*)
 
}