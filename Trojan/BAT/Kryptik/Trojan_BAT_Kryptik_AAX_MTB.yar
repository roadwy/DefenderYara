
rule Trojan_BAT_Kryptik_AAX_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.AAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {9a 0c 08 19 8d [0-04] 25 16 7e [0-04] a2 25 17 7e [0-04] a2 25 18 72 [0-04] a2 28 [0-04] 26 20 00 08 00 00 0a 2b 00 06 2a } //10
		$a_80_1 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  2
		$a_80_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_3 = {41 63 74 69 76 61 74 6f 72 } //Activator  2
		$a_80_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}
rule Trojan_BAT_Kryptik_AAX_MTB_2{
	meta:
		description = "Trojan:BAT/Kryptik.AAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_03_0 = {0b 07 1f 21 8c [0-04] 16 28 [0-04] 07 1f 7e 8c [0-04] 16 28 [0-0f] 13 06 11 06 2c 3d 06 1f 21 8c [0-04] 07 1f 0e 8c [0-09] 1f 5e 8c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 2b 17 06 07 28 } //10
		$a_80_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_2 = {41 63 74 69 76 61 74 6f 72 } //Activator  2
		$a_80_3 = {46 6f 72 4e 65 78 74 43 68 65 63 6b 4f 62 6a } //ForNextCheckObj  2
		$a_80_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
		$a_80_5 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=20
 
}