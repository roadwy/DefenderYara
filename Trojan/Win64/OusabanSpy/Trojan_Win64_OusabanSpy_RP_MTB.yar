
rule Trojan_Win64_OusabanSpy_RP_MTB{
	meta:
		description = "Trojan:Win64/OusabanSpy.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 43 20 88 03 48 89 d1 48 8b 52 f8 8a 1d 02 84 4f 00 eb 5b b8 00 01 00 00 f0 0f b0 23 74 80 f3 90 48 8d 05 78 8d 4f 00 80 38 00 75 e7 48 89 ce b9 } //1
		$a_01_1 = {41 81 38 d0 ff 13 00 75 31 48 83 ee 20 48 8b 06 48 8b 56 08 48 89 50 08 48 89 02 31 c0 88 05 e2 8d 4f 00 48 89 f1 31 d2 41 b8 00 80 00 00 e8 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}