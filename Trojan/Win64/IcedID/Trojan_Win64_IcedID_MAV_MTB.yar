
rule Trojan_Win64_IcedID_MAV_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 74 75 67 6a 68 73 68 61 67 73 64 6d 61 6a 68 } //1 ntugjhshagsdmajh
		$a_01_1 = {41 6f 78 56 47 78 55 68 4d 53 33 37 75 35 } //1 AoxVGxUhMS37u5
		$a_01_2 = {44 53 76 57 6a 63 4c 6e 30 74 } //1 DSvWjcLn0t
		$a_01_3 = {48 36 73 6d 6b 6f 43 77 49 6e } //1 H6smkoCwIn
		$a_01_4 = {59 58 53 42 77 45 38 64 71 76 59 } //1 YXSBwE8dqvY
		$a_01_5 = {67 45 7a 37 78 59 75 51 6f } //1 gEz7xYuQo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win64_IcedID_MAV_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 83 c0 04 8b 83 90 01 04 33 43 90 01 01 83 f0 90 01 01 89 43 0c 8b 83 90 01 04 83 e8 90 01 01 31 43 90 01 01 b8 90 01 04 2b 83 90 01 04 01 43 90 01 01 8b 4b 90 01 01 44 89 8b 90 01 04 8d 81 90 01 04 8b 8b 90 01 04 31 43 90 01 01 2b 4b 90 01 01 8b 43 90 01 01 81 c1 90 01 04 2d 90 01 04 0f af c8 89 8b 90 01 04 8b 83 90 01 04 01 43 90 01 01 49 81 f8 90 01 04 7c 90 00 } //1
		$a_01_1 = {43 65 6c 6c 43 6c 65 61 72 49 6d 6d } //1 CellClearImm
		$a_01_2 = {48 63 72 7a 61 34 68 32 } //1 Hcrza4h2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}