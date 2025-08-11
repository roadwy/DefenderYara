
rule Trojan_Win64_Tedy_PGL_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 50 48 3b c5 7d 17 48 05 ?? ?? ?? ?? 48 8d 4c 24 40 48 89 44 24 40 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}