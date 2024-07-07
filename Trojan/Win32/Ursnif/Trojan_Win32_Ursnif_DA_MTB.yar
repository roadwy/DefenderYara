
rule Trojan_Win32_Ursnif_DA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a da 89 15 90 01 04 02 db 80 c3 0d 8b 54 24 28 8a c1 2a 44 24 10 81 c6 04 9c 01 01 2c 52 89 35 90 01 04 02 d8 8b 44 24 24 89 34 02 83 c0 04 8b 15 90 01 04 89 44 24 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 55 2f 02 d3 f6 ea 8a d0 8b 45 1c 05 90 01 04 89 45 24 fe c8 f6 e9 02 d0 02 55 47 30 14 31 83 3d 90 01 04 00 74 90 00 } //1
		$a_01_1 = {55 51 50 58 59 5d 59 5b c2 } //1
		$a_01_2 = {33 c0 0f af c8 8b c6 33 d2 f7 f1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}