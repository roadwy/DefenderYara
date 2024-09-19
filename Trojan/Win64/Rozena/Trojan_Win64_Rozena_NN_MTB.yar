
rule Trojan_Win64_Rozena_NN_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 c7 44 24 48 00 00 00 00 48 8b 0d ?? a6 2e 00 65 48 8b 09 48 8b 09 48 8b 49 } //3
		$a_03_1 = {48 8d 54 24 20 48 89 91 ?? ?? ?? ?? 48 8b 44 24 ?? 45 0f 57 ff 4c 8b 35 ?? a6 2e 00 65 4d 8b 36 4d 8b 36 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}