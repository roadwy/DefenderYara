
rule Trojan_Win64_Lazy_GVA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {48 8b 45 e0 c7 05 ?? ?? ?? ?? 88 15 00 00 48 8b 4d f8 8a 14 01 4c 8b 45 e8 41 88 14 00 48 05 01 00 00 00 4c 8b 4d f0 4c 39 c8 48 89 45 e0 } //1
		$a_01_1 = {52 65 72 75 65 65 6c 66 68 6e 72 73 72 57 72 6c } //1 RerueelfhnrsrWrl
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}