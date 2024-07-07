
rule Trojan_Win32_LockbitCrypt_SA_MTB{
	meta:
		description = "Trojan:Win32/LockbitCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b fb c1 e7 04 81 3d 90 01 04 6f 03 00 00 75 0a 6a 00 6a 00 ff 15 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 8b f3 c1 ee 05 03 75 90 01 01 03 f9 03 d3 33 fa 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 08 75 90 00 } //1
		$a_01_1 = {51 6a 40 50 52 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_LockbitCrypt_SA_MTB_2{
	meta:
		description = "Trojan:Win32/LockbitCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 5d fc 8b fb c1 e7 04 81 3d 90 01 08 75 90 01 01 6a 00 6a 00 ff 15 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 8b f3 c1 ee 05 03 75 90 01 01 03 f9 03 d3 33 fa 81 3d 90 01 08 c7 05 90 01 08 75 90 00 } //1
		$a_03_1 = {8d 64 24 00 81 f9 90 01 04 75 90 01 01 8b 15 90 01 04 8d 4c 24 90 01 01 51 6a 40 50 52 ff 15 90 01 04 a1 90 01 04 3d 90 01 04 75 90 01 01 33 c0 33 c9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}