
rule Trojan_Linux_SAgnt_L_MTB{
	meta:
		description = "Trojan:Linux/SAgnt.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 76 08 48 89 fa 48 81 fe ?? 85 72 00 74 15 31 c0 80 3e 2a 74 12 bf ?? 85 72 00 b9 18 00 00 00 f3 a6 75 04 ?? ?? ?? ?? f3 c3 0f 1f 44 00 00 } //1
		$a_01_1 = {95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 48 95 d1 ff 70 95 d1 ff 70 95 d1 ff 48 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 95 d1 ff 70 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}