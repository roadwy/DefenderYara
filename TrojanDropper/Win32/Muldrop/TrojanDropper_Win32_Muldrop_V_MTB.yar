
rule TrojanDropper_Win32_Muldrop_V_MTB{
	meta:
		description = "TrojanDropper:Win32/Muldrop.V!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 00 55 00 c5 00 69 00 c9 00 6f 00 72 00 cf 00 d1 00 } //02 00 
		$a_01_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 72 00 f9 00 6e 00 61 00 6d 00 65 00 20 00 22 00 } //00 00 
	condition:
		any of ($a_*)
 
}