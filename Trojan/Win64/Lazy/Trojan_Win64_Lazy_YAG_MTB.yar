
rule Trojan_Win64_Lazy_YAG_MTB{
	meta:
		description = "Trojan:Win64/Lazy.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 3f 32 c3 90 13 48 8d 3f 48 8d 3f 90 13 48 8d 3f 2a c3 90 13 48 8d 3f 48 8d 3f 90 13 48 8d 3f 48 8d 3f 90 13 32 c3 48 8d 3f 90 13 2a c3 48 8d 3f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}