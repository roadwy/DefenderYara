
rule Trojan_BAT_Kryptik_AAU_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.AAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_03_0 = {9a 0c 08 19 8d [0-04] 25 16 7e [0-04] a2 25 17 7e [0-04] a2 25 18 72 [0-04] a2 28 [0-04] 26 20 00 08 00 00 0a 2b 00 06 2a } //10
		$a_80_1 = {46 61 6c 6c 62 61 63 6b 42 75 66 66 65 72 } //FallbackBuffer  2
		$a_80_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  2
		$a_80_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=18
 
}