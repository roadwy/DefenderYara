
rule Trojan_BAT_Kryptik_SL_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_03_0 = {0b 07 14 72 [0-04] 18 8d [0-04] 25 16 1e 8d [0-04] 25 d0 [0-04] 28 [0-04] a2 25 17 1e } //10
		$a_03_1 = {a2 14 14 28 [0-09] 0c 08 14 72 [0-04] 19 8d [0-04] 25 16 02 a2 25 17 16 8c [0-04] a2 25 18 20 [0-09] a2 14 14 28 [0-09] 0a 2b 00 06 2a } //10
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  2
		$a_80_3 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //LateBinding  2
		$a_80_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //TransformFinalBlock  2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=26
 
}