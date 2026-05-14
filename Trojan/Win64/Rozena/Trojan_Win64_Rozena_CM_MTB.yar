
rule Trojan_Win64_Rozena_CM_MTB{
	meta:
		description = "Trojan:Win64/Rozena.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 d2 4c 8b 6c 24 ?? c7 44 24 ?? 40 00 00 00 41 b9 00 10 00 00 4c 89 f1 ff 15 } //2
		$a_03_1 = {49 89 d9 49 89 f0 4c 89 f1 48 c7 44 24 ?? 00 00 00 00 49 89 c4 48 89 c2 ff 15 ?? ?? ?? ?? 45 31 c0 4c 89 ea 4c 89 e1 ff 15 ?? ?? ?? ?? 4c 89 e9 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}