
rule Trojan_Win64_SalatStealer_SS_MTB{
	meta:
		description = "Trojan:Win64/SalatStealer.SS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 50 c7 44 24 20 40 00 00 00 31 d2 4d 89 f0 41 b9 00 30 00 00 e8 a9 b3 01 00 48 85 c0 0f 84 40 01 00 00 49 89 c7 48 8d 84 24 10 01 00 00 48 83 20 00 41 b9 00 10 00 00 4c 39 ce 4c 0f 42 ce 48 8b 4c 24 50 48 89 44 24 20 4c 89 fa 49 89 f8 e8 75 b3 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}