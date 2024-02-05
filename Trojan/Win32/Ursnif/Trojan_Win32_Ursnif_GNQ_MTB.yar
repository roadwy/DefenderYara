
rule Trojan_Win32_Ursnif_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 10 0f b6 04 97 66 31 04 91 8b 54 24 20 8a ca 8b 44 24 14 80 f1 69 02 4c 70 0a } //01 00 
		$a_01_1 = {73 74 77 6e 34 30 34 79 61 31 33 2e 64 6c 6c } //01 00 
		$a_01_2 = {50 46 72 64 6e 65 35 52 4c } //00 00 
	condition:
		any of ($a_*)
 
}