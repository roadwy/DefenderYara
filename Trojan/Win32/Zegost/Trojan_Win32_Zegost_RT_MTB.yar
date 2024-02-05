
rule Trojan_Win32_Zegost_RT_MTB{
	meta:
		description = "Trojan:Win32/Zegost.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 49 00 a1 90 01 04 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 04 8a 0d 90 01 04 30 0c 37 83 fb 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}