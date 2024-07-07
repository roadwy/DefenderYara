
rule Trojan_Win64_Farfli_RD_MTB{
	meta:
		description = "Trojan:Win64/Farfli.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 0f b6 0c 11 45 8d 49 ff 30 0a 48 8d 52 ff 41 83 c0 ff 75 eb 41 8d 40 01 42 0f b6 04 10 43 30 04 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}