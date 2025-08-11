
rule Trojan_Win64_Redline_GZZ_MTB{
	meta:
		description = "Trojan:Win64/Redline.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 21 21 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 00 00 00 00 53 48 47 65 74 46 6f 6c 64 65 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}