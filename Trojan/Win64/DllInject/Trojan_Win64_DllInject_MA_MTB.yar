
rule Trojan_Win64_DllInject_MA_MTB{
	meta:
		description = "Trojan:Win64/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 33 c0 48 ff c0 c3 74 24 10 57 48 83 ec 20 49 8b f8 8b da 48 8b f1 83 fa 01 75 05 e8 ?? ?? ?? ?? 4c 8b c7 8b d3 48 8b ce 48 8b 5c 24 30 48 8b 74 24 38 48 83 c4 20 5f e9 a7 fe ff ff } //5
		$a_01_1 = {22 20 0b 02 0a 00 00 96 25 00 00 c4 08 00 00 00 00 00 ac 73 21 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}