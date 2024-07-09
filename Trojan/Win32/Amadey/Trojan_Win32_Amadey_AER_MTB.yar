
rule Trojan_Win32_Amadey_AER_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 e9 97 22 ff 34 df 38 68 ?? 17 fd ed e4 ?? 8b 11 47 88 20 38 0b 11 e9 b2 61 6d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}