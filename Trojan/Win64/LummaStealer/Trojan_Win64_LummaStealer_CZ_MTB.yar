
rule Trojan_Win64_LummaStealer_CZ_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 40 20 48 89 84 24 08 02 00 00 8b 05 f6 81 03 00 8d 48 ff 0f af c8 f6 c1 01 b8 f9 69 e4 ce b9 76 13 e6 8a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}