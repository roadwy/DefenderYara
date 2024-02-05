
rule Trojan_Win32_SpyStealer_AQ_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 4c 24 18 8b 44 24 18 31 44 24 10 2b 7c 24 10 68 90 02 04 8d 44 24 20 50 e8 90 02 04 83 6c 24 20 01 0f 85 90 00 } //01 00 
		$a_01_1 = {03 44 24 28 89 44 24 10 8b 44 24 18 03 44 24 1c 89 44 24 14 8b 54 24 14 31 54 24 10 8b cb c1 e9 05 03 cd } //02 00 
		$a_01_2 = {81 44 24 24 e9 59 6c 17 81 44 24 7c 0e aa 3f 2c 81 44 24 10 1e c6 bf 46 81 ac 24 00 01 00 00 49 37 33 20 81 6c 24 34 88 91 28 52 81 44 24 40 ed a6 cf 5f 81 84 24 bc 00 00 00 bc c5 1f 54 81 ac 24 94 00 00 00 0e 83 20 39 81 ac 24 dc 00 00 00 ed 92 8b 29 81 04 24 46 e1 6e 70 } //00 00 
	condition:
		any of ($a_*)
 
}