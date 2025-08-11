
rule Trojan_Win32_LummaStealer_ZZA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 46 82 b7 6f 29 d9 11 d0 0b 2c 95 58 f3 dd 6c 4b a3 76 13 8c a7 e2 df 3a 24 fc 69 75 81 e7 a6 aa 97 a8 65 93 5d ec a0 23 61 25 0c 05 19 71 a6 c7 6c d7 99 17 db f5 38 1a 57 39 fe 13 a2 fa a6 10 40 00 04 81 14 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}