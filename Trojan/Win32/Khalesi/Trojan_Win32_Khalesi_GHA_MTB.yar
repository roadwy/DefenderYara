
rule Trojan_Win32_Khalesi_GHA_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.GHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 17 89 c3 81 c7 90 01 04 48 39 f7 75 ec 81 e8 90 01 04 21 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}