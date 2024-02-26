
rule Trojan_Win32_DarkGate_C_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {32 c2 f6 d0 5a 88 02 ff 06 4b } //02 00 
		$a_03_1 = {8b 06 0f b6 44 05 90 01 01 31 05 90 01 04 ff 06 4b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}