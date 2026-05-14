
rule Trojan_Win64_ACRStealer_GVA_MTB{
	meta:
		description = "Trojan:Win64/ACRStealer.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 15 e0 ac 81 00 48 8b 45 f8 48 01 d0 44 0f b6 00 b9 76 00 00 00 48 8b 45 f8 ba 00 00 00 00 48 f7 f1 48 8d 05 3d b1 81 00 0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 8d 3f 4d 87 d2 48 83 45 f8 01 b8 16 00 00 00 48 39 45 f8 72 aa } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}