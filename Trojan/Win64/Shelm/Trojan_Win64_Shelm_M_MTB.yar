
rule Trojan_Win64_Shelm_M_MTB{
	meta:
		description = "Trojan:Win64/Shelm.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 37 41 8b de 49 03 f1 48 8d 7f 90 01 01 0f be 0e 48 ff c6 c1 cb 90 01 01 03 d9 84 c9 90 00 } //02 00 
		$a_03_1 = {41 8d 0c 30 45 03 90 01 01 80 34 90 01 02 44 3b c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}