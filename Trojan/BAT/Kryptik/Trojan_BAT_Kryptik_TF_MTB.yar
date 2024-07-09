
rule Trojan_BAT_Kryptik_TF_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.TF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 17 d6 18 28 [0-16] 02 18 d6 19 28 [0-16] 02 19 d6 1a 28 [0-16] 02 1a d6 1b 28 [0-16] 02 1b d6 1c } //10
		$a_80_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //GetExportedTypes  2
		$a_80_2 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //CreateDelegate  2
		$a_80_3 = {57 65 62 52 65 71 75 65 73 74 } //WebRequest  2
		$a_80_4 = {57 65 62 52 65 73 70 6f 6e 73 65 } //WebResponse  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}