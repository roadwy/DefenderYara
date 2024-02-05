
rule Trojan_Win32_Ursnif_H_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 45 90 01 01 03 30 8b 4d 90 01 01 89 31 90 02 20 8b e5 90 00 } //01 00 
		$a_02_1 = {81 c1 3c 5e 00 00 a1 90 02 40 31 0d 90 02 10 c7 05 90 02 20 a1 90 02 20 01 05 90 02 20 8b 15 90 02 20 a1 90 02 10 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}