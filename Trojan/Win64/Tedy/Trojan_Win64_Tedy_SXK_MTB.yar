
rule Trojan_Win64_Tedy_SXK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {aa bb cc dd c7 45 ?? ee ff 11 22 c7 45 ?? 33 44 55 66 48 c7 45 ?? 29 00 00 00 c6 45 } //20
		$a_03_1 = {48 ba 87 7d 33 57 6b 7a 5b a9 48 89 85 ?? ?? ?? ?? 48 8b cb 48 8b f0 e8 ?? ?? ?? ?? 48 ba 65 9e 4d 35 47 f8 20 65 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}