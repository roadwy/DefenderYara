
rule Trojan_Win64_Mikey_NM_MTB{
	meta:
		description = "Trojan:Win64/Mikey.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 c1 e2 20 48 0b d0 48 89 55 90 01 01 48 8b 45 10 24 90 01 01 3c 06 75 32 8b 05 e4 1d 01 00 83 c8 08 c7 05 90 00 } //3
		$a_03_1 = {f6 45 e8 20 89 05 cd 1d 01 00 74 13 83 c8 20 c7 05 90 01 04 05 00 00 00 89 05 90 01 04 48 8b 5c 24 38 33 c0 48 8b 7c 24 40 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}