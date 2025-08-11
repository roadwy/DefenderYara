
rule Trojan_Win64_BlackWidow_GVO_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 2b c8 48 8b 45 ?? 0f b6 4c 0d ?? 43 32 4c 10 ff 41 88 4c 00 ff 3b 5d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}