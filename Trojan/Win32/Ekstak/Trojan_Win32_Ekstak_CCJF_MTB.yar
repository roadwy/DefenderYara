
rule Trojan_Win32_Ekstak_CCJF_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a ff 68 10 b5 65 00 68 90 62 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 20 b2 65 00 33 d2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}