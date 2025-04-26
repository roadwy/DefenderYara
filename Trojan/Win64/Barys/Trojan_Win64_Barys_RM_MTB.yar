
rule Trojan_Win64_Barys_RM_MTB{
	meta:
		description = "Trojan:Win64/Barys.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 7c 24 70 48 89 d9 e8 f1 03 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 02 00 00 00 48 89 d9 ba 00 00 00 40 41 b8 02 00 00 00 45 31 c9 ff 15 79 3e 02 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}