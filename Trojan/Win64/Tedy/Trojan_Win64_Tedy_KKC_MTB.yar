
rule Trojan_Win64_Tedy_KKC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 2c 48 63 c9 8b 54 24 2c 69 d2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 66 33 54 4c 30 8b 4c 24 2c 48 63 c9 66 89 54 4c 30 ff 44 24 2c 8b 4c 24 2c 83 f9 0c } //20
		$a_01_1 = {52 45 4d 55 53 20 4c 4f 47 } //10 REMUS LOG
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}