
rule Trojan_Win32_Convagent_GMB_MTB{
	meta:
		description = "Trojan:Win32/Convagent.GMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 88 18 c6 40 01 00 5b c3 90 01 01 8b 44 24 04 b9 01 00 00 00 8b 10 83 c0 04 85 d2 7e 90 01 01 56 8b 30 83 c0 04 0f af ce 4a 75 90 01 01 8b 54 24 0c 5e 89 0a c3 8b 54 24 08 89 0a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}