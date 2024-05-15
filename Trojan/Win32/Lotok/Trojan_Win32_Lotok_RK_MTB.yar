
rule Trojan_Win32_Lotok_RK_MTB{
	meta:
		description = "Trojan:Win32/Lotok.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 04 02 99 f7 ff 8b c6 80 c2 90 01 01 30 11 59 99 f7 f9 ff 45 90 01 01 85 d2 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}