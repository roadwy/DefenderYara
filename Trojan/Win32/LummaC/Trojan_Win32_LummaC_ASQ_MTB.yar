
rule Trojan_Win32_LummaC_ASQ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ASQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 23 00 83 63 04 00 e8 ?? ?? ?? ?? 8b 4c 24 44 83 c4 0c 8b 44 24 3c 8a 4c 0c 40 30 0c 38 83 7b 04 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}