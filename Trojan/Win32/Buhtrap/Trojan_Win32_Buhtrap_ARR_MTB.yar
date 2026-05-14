
rule Trojan_Win32_Buhtrap_ARR_MTB{
	meta:
		description = "Trojan:Win32/Buhtrap.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 32 54 04 ?? 0f be c0 6b c0 ?? 32 d0 88 54 24 ?? 3b f7 73 } //15
		$a_01_1 = {5b 2d 5d 20 4d 61 6c 66 6f 72 6d 65 64 20 66 69 65 6c 64 3a 20 25 6c 78 } //3 [-] Malformed field: %lx
		$a_01_2 = {49 6e 76 61 6c 69 64 20 70 61 79 6c 6f 61 64 3a } //2 Invalid payload:
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=20
 
}