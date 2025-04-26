
rule Trojan_BAT_AsyncRAT_AMD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1d 5d 16 fe 01 [0-10] 61 b4 9c 00 00 [0-05] 17 d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}