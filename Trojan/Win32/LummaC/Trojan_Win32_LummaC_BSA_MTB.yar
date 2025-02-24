
rule Trojan_Win32_LummaC_BSA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 eb f9 8b 0d ?? d5 ?? 00 56 57 bf 4e e6 40 bb be 00 00 ff ff 3b cf 74 04 85 ce 75 26 e8 2c 00 00 00 8b c8 3b cf 75 07 b9 4f e6 40 bb eb 0e 85 ce 75 0a 0d 11 47 00 00 c1 e0 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}