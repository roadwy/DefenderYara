
rule Trojan_Win32_Fareit_SK_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 33 c9 8b d9 03 d8 73 05 e8 da 38 f9 ff 30 13 41 81 f9 47 5c 00 00 75 ea } //00 00 
	condition:
		any of ($a_*)
 
}