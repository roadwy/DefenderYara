
rule Trojan_MacOS_SAgnt_D_MTB{
	meta:
		description = "Trojan:MacOS/SAgnt.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {40 8a 31 40 84 f6 74 ?? 40 38 f0 75 ?? 48 ff c1 8a 02 48 ff c2 84 c0 75 ?? 31 c0 } //1
		$a_03_1 = {89 d1 80 e1 38 49 89 f0 49 d3 e8 44 30 07 48 83 c2 08 48 ff c7 48 83 fa 50 75 ?? c6 40 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}