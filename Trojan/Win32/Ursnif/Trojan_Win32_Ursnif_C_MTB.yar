
rule Trojan_Win32_Ursnif_C_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ff c7 05 90 02 30 01 1d 90 01 04 8b ff a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //01 00 
		$a_02_1 = {83 c4 08 8b 45 90 01 01 89 45 90 01 01 8b 0d 90 01 04 03 4d 90 01 01 89 0d 90 01 04 8b 55 90 01 01 89 55 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}