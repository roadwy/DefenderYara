
rule Trojan_Win64_Tedy_WL_MTB{
	meta:
		description = "Trojan:Win64/Tedy.WL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 40 10 48 89 05 9f 0d 01 00 31 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}