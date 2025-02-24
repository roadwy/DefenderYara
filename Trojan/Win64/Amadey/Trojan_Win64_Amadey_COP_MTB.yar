
rule Trojan_Win64_Amadey_COP_MTB{
	meta:
		description = "Trojan:Win64/Amadey.COP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 a5 f6 ff ff 48 89 05 42 59 00 00 48 8d 15 e3 44 00 00 48 8d 0d ec 44 00 00 e8 8b f6 ff ff 48 89 05 30 59 00 00 48 8d 15 e9 44 00 00 48 8d 0d fa 44 00 00 e8 71 f6 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}