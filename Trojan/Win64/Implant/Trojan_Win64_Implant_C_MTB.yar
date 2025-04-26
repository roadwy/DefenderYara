
rule Trojan_Win64_Implant_C_MTB{
	meta:
		description = "Trojan:Win64/Implant.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {c7 45 d7 43 72 65 61 c7 45 db 74 65 46 69 c7 45 df 6c 65 4d 61 c7 45 e3 70 70 69 6e 66 c7 45 e7 67 41 } //2
		$a_01_1 = {c7 45 a7 4d 61 70 56 c7 45 ab 69 65 77 4f c7 45 af 66 46 69 6c 66 c7 45 b3 65 } //2
		$a_01_2 = {c7 45 c7 55 6e 6d 61 c7 45 cb 70 56 69 65 c7 45 cf 77 4f 66 46 c7 45 d3 69 6c 65 } //2
		$a_01_3 = {c7 45 b7 56 69 72 74 c7 45 bb 75 61 6c 50 c7 45 bf 72 6f 74 65 66 c7 45 c3 63 74 } //2
		$a_01_4 = {c7 45 ef 77 69 6e 64 c7 45 f3 6f 77 73 2e c7 45 f7 73 74 6f 72 c7 45 fb 61 67 65 2e c7 45 ff 64 6c 6c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=2
 
}