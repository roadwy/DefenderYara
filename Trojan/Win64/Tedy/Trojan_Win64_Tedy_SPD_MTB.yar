
rule Trojan_Win64_Tedy_SPD_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 85 c9 0f 84 ?? 00 00 00 48 8b 83 00 00 00 00 4c 31 e8 48 89 83 00 00 00 00 48 ff c9 [0-32] e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}