
rule Trojan_Win64_Cobaltstrike_CTI_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.CTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 0f b6 c0 48 98 8b 44 85 a0 0f b6 c0 c1 e0 06 89 c1 8b 85 a8 01 00 00 48 98 48 8d 50 03 48 8b 85 d0 01 00 00 48 01 d0 0f b6 00 0f b6 c0 48 98 8b 44 85 a0 09 c1 8b 85 a4 01 00 00 48 98 48 8d 50 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}