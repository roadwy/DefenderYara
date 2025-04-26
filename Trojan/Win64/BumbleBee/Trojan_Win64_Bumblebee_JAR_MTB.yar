
rule Trojan_Win64_Bumblebee_JAR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.JAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af e8 b8 f6 1a 00 00 99 41 f7 7c cd 00 48 8b 8c 24 a0 00 00 00 41 03 92 bc 6a 00 00 44 0b da 44 89 1d 8a d4 10 00 49 63 c3 4c 8b 9c 24 a8 00 00 00 42 0f b6 04 20 0b c3 99 41 f7 f9 42 30 04 19 4c 63 0d 81 d4 10 00 44 0f b7 05 95 d4 10 00 88 1d 7a d4 10 00 45 8b d0 4a 8b 04 ce 48 2b 86 f0 d4 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}