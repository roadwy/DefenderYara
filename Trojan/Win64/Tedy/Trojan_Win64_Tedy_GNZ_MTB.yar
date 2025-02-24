
rule Trojan_Win64_Tedy_GNZ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {ed 30 e6 33 6a ?? 24 ?? a8 ?? 53 52 01 ba ?? ?? ?? ?? 01 54 f5 } //5
		$a_03_1 = {01 c7 31 04 34 a3 ?? ?? ?? ?? ?? ?? ?? ?? 2b 11 2e 9d c8 67 03 ?? 08 e6 13 09 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}