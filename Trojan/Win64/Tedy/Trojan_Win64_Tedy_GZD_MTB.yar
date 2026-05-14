
rule Trojan_Win64_Tedy_GZD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f3 41 0f 5c f5 f3 41 0f 5c fc f3 45 0f 5c c6 b9 53 00 00 00 44 0f 28 fe 44 0f 28 de 44 0f 28 cf 45 0f 28 d0 ff 15 ?? ?? ?? ?? 66 85 c0 79 ?? 41 0f 28 f5 f3 45 0f 58 f0 f3 44 0f 58 e7 f3 41 0f 58 f7 45 0f 28 c6 45 0f 28 d6 41 0f 28 fc 44 0f 28 cf 44 0f 28 de b9 41 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}