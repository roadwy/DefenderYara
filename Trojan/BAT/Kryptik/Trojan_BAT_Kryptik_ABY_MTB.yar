
rule Trojan_BAT_Kryptik_ABY_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_03_0 = {09 11 09 07 11 09 18 5a 18 [0-05] 1f 10 [0-05] d2 9c } //10
		$a_80_1 = {41 75 74 6f 53 63 61 6c 65 42 61 73 65 53 69 7a 65 } //AutoScaleBaseSize  2
		$a_80_2 = {53 75 62 73 74 72 69 6e 67 } //Substring  2
		$a_80_3 = {54 6f 49 6e 74 33 32 } //ToInt32  2
		$a_80_4 = {52 65 70 6c 61 63 65 } //Replace  2
		$a_80_5 = {49 6e 76 6f 6b 65 } //Invoke  2
		$a_80_6 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //LateBinding  2
		$a_80_7 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_8 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //GetAssemblies  2
		$a_80_9 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2) >=20
 
}