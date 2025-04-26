
rule Trojan_Win64_Bumblebee_TRA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.TRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 2b c2 48 01 83 48 03 00 00 48 8b 83 ?? ?? ?? ?? 48 05 d8 28 00 00 48 01 81 58 02 00 00 48 63 93 c0 03 00 00 48 8b 43 30 48 8b 4b 08 8a 14 0a 41 32 14 00 48 8b 43 70 41 88 14 00 48 8b 93 78 02 00 00 81 ba 20 03 00 00 c8 2a 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}