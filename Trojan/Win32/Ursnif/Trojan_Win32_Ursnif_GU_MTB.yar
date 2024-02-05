
rule Trojan_Win32_Ursnif_GU_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a c1 2a c1 04 5a 34 37 32 c1 34 37 2a c1 04 5a c0 c0 07 c0 c0 07 2a c1 2a c1 34 37 c0 c0 07 c0 c8 07 2c 5a aa 4a 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}