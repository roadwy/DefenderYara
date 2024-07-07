
rule Trojan_Win32_LummaC_KAA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 88 8a 84 05 90 01 04 30 04 0b 43 3b 9d 90 01 04 89 5d 90 01 01 8b 5d 90 01 01 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}