
rule Trojan_Win64_Cobaltstrike_MT_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 28 48 89 38 48 8b 44 24 40 48 89 44 24 30 b9 01 00 00 00 ff d3 48 89 44 24 38 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_MT_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f af c2 29 c1 89 c8 48 63 d0 48 8d 05 90 01 04 0f b6 04 02 44 31 c8 41 88 00 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 45 e8 48 39 c2 0f 82 90 00 } //02 00 
		$a_01_1 = {41 41 41 57 69 65 6a 5a 6d 71 4c 76 6d 52 61 53 57 73 71 44 6f 4f 72 71 } //02 00  AAAWiejZmqLvmRaSWsqDoOrq
		$a_01_2 = {41 41 5a 6b 50 47 69 7a 76 49 67 74 53 56 4d } //00 00  AAZkPGizvIgtSVM
	condition:
		any of ($a_*)
 
}