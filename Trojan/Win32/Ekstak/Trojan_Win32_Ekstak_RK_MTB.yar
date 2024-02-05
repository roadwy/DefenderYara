
rule Trojan_Win32_Ekstak_RK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 05 7c 4b 08 01 68 90 01 04 e8 90 01 01 00 00 00 59 a3 90 01 01 4b 08 01 e8 90 01 01 00 00 00 8b c8 b8 90 01 04 33 d2 f7 f1 31 05 90 01 01 4b 08 01 e8 90 01 02 00 00 33 c0 50 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}