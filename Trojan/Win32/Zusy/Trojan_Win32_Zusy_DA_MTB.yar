
rule Trojan_Win32_Zusy_DA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.DA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7b 5c e9 eb 33 7a fa 5a 81 48 04 52 d8 49 c2 c9 83 d2 75 b2 a1 15 93 3d bb b9 af 25 b4 21 3b a5 53 11 be b5 26 2a 1b 6c 57 29 2f 25 3b 2e 16 85 2b 35 39 41 a3 fd 27 d5 4b b1 5f 21 3f b5 f1 28 db 31 33 3d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}