
rule Trojan_Win64_Cobaltstrike_BCD_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.BCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 0f b6 40 02 c3 } //1
		$a_01_1 = {e8 81 fe ff ff 88 45 ff 80 7d ff 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}