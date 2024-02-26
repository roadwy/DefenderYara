
rule Trojan_Win32_Amadey_ENY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ENY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 04 24 0d a1 b8 cf bc 02 0f af 04 24 05 c3 9e 26 00 a3 b8 cf bc 02 0f b7 05 ba cf bc 02 25 ff 7f 00 00 } //01 00 
		$a_01_1 = {30 04 1e 83 ff 0f 75 } //00 00 
	condition:
		any of ($a_*)
 
}