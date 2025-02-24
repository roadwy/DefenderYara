
rule Trojan_Win64_Tedy_GCM_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 88 45 f6 80 75 f6 aa 48 8b 45 f8 28 45 f6 0f b6 45 f7 30 45 f6 0f b6 45 f6 c1 e0 04 89 c2 0f b6 45 f6 c0 e8 04 09 d0 88 45 f6 f6 55 f6 0f b6 5d f6 48 8b 45 f8 48 89 c2 48 8b 4d 20 e8 28 80 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}