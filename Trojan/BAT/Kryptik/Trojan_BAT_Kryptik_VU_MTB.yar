
rule Trojan_BAT_Kryptik_VU_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 09 00 00 "
		
	strings :
		$a_03_0 = {19 8d 0d 00 00 01 25 16 7e [0-02] 00 00 04 a2 25 17 7e [0-02] 00 00 04 a2 25 18 72 [0-03] 70 a2 } //10
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  2
		$a_80_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_4 = {41 63 74 69 76 61 74 6f 72 } //Activator  2
		$a_80_5 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  2
		$a_80_6 = {43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //CryptoServiceProvider  2
		$a_80_7 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //TransformFinalBlock  2
		$a_80_8 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2) >=20
 
}