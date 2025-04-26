
rule Trojan_Win64_Rozena_BS_MTB{
	meta:
		description = "Trojan:Win64/Rozena.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 0f b6 1c 0a 45 31 c3 44 88 1c 3e 48 ff c7 4c 89 c8 4c 89 d2 48 39 fa 7e } //2
		$a_01_1 = {49 ff c1 0f b6 14 17 44 31 d2 4d 39 c8 73 } //2
		$a_01_2 = {43 88 54 21 ff 48 ff c1 4c 89 d8 4c 89 e2 48 39 cb } //2
		$a_01_3 = {78 6f 72 73 37 61 6a 73 75 61 6a 61 73 } //1 xors7ajsuajas
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}