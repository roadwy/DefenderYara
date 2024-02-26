
rule Trojan_Win32_Sdum_GMD_MTB{
	meta:
		description = "Trojan:Win32/Sdum.GMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 07 8b d1 83 e2 03 8a 54 3a 0c 03 c1 30 10 41 3b 4f 04 } //00 00 
	condition:
		any of ($a_*)
 
}