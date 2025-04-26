
rule Trojan_Win64_Bumblebee_DSN_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.DSN!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 84 24 90 00 00 00 81 c5 5a 2b 00 00 49 8b 88 08 03 00 00 48 8b 81 d0 01 00 00 48 35 45 9a 10 00 49 89 80 60 01 00 00 48 c7 81 a8 03 00 00 06 ad ee 03 49 8b 88 28 03 00 00 48 8b 81 f8 00 00 00 48 01 41 40 49 8b 80 28 03 00 00 48 ff 88 f8 00 00 00 49 8b 80 a0 03 00 00 49 8b 90 18 03 00 00 48 8b 88 d0 01 00 00 48 81 c1 77 16 00 00 48 01 8a 20 01 00 00 81 ef ee 06 00 00 } //1
		$a_01_1 = {51 55 6b 30 32 34 } //1 QUk024
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}