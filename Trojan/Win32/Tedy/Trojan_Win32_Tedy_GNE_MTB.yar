
rule Trojan_Win32_Tedy_GNE_MTB{
	meta:
		description = "Trojan:Win32/Tedy.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e c6 44 24 ?? 72 c6 44 24 ?? 65 c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 63 c6 44 24 ?? 00 8b f7 8d 44 24 ?? 8a 18 8a cb 3a 1e } //5
		$a_03_1 = {40 00 00 40 2e 64 61 74 61 00 00 00 ?? ?? 00 00 00 60 00 00 00 ?? 00 00 00 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 76 6d 70 30 00 00 00 20 0e } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}