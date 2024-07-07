
rule Trojan_Win64_Rozena_XZ_MTB{
	meta:
		description = "Trojan:Win64/Rozena.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 8b 4c 24 40 48 89 08 0f 57 c0 0f 11 40 08 48 8b 54 24 48 48 89 50 18 0f 11 40 20 48 c7 40 30 00 00 00 00 48 8b 15 70 af 0d 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}