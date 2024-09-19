
rule Trojan_Win64_Cobaltstrike_ADG_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 37 64 61 53 2e 64 6c 6c } //1 F7daS.dll
		$a_01_1 = {80 74 05 cf fa 49 03 c4 48 83 f8 0d 72 f2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Cobaltstrike_ADG_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c0 89 44 24 30 8b 44 24 34 39 44 24 30 73 20 48 63 44 24 30 48 8b 4c 24 38 0f be 04 01 83 f0 32 48 63 4c 24 30 48 8b 54 24 38 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}