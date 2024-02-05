
rule Trojan_Win32_Raccrypt_GDD_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GDD!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 08 83 c4 10 5d c3 81 00 03 35 ef c6 c3 01 08 c3 } //00 00 
	condition:
		any of ($a_*)
 
}