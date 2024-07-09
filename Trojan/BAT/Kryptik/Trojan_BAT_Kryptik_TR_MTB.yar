
rule Trojan_BAT_Kryptik_TR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.TR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 00 03 28 [0-04] 72 [0-04] 6f [0-04] 0b 07 19 8d [0-04] 25 16 7e [0-04] a2 25 17 7e [0-04] a2 25 18 72 [0-04] a2 28 [0-04] 26 20 [0-04] 0a 2b 00 06 2a } //10
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //FromBase64CharArray  2
		$a_80_2 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_3 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //NewLateBinding  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=16
 
}