
rule Trojan_Win64_Phave_GVA_MTB{
	meta:
		description = "Trojan:Win64/Phave.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 0f b6 00 32 85 be 11 00 00 48 8b 8d c8 11 00 00 48 8b 95 18 12 00 00 48 01 ca 32 85 bf 11 00 00 88 02 48 83 85 18 12 00 00 01 48 8b 85 18 12 00 00 48 3b 85 10 12 00 00 72 b5 } //2
		$a_01_1 = {48 01 d0 0f b6 00 48 8b 8d b8 11 00 00 48 8b 95 f8 11 00 00 48 01 ca 32 85 af 11 00 00 88 02 48 83 85 f8 11 00 00 01 48 8b 85 f8 11 00 00 48 3b 85 f0 11 00 00 72 bb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}