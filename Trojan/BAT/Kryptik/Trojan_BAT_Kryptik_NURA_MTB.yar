
rule Trojan_BAT_Kryptik_NURA_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.NURA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 31 41 37 30 46 35 32 30 2d 36 33 37 33 2d 34 35 44 31 2d 42 45 35 33 2d 45 38 43 33 44 36 37 44 46 35 41 37 } //10 $1A70F520-6373-45D1-BE53-E8C3D67DF5A7
		$a_01_1 = {42 53 54 52 4d 61 72 73 68 61 6c 65 72 } //1 BSTRMarshaler
		$a_01_2 = {46 4c 75 78 43 65 6e 74 65 72 } //1 FLuxCenter
		$a_01_3 = {4f 62 6a 65 63 74 49 64 65 6e 74 69 66 69 65 72 } //1 ObjectIdentifier
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}