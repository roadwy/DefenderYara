
rule Trojan_BAT_DCRat_RDP_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 31 31 39 66 36 34 33 2d 39 34 33 66 2d 34 37 31 34 2d 61 31 35 39 2d 31 39 61 62 39 32 31 38 62 30 61 39 } //2 a119f643-943f-4714-a159-19ab9218b0a9
		$a_01_1 = {45 76 69 6c 50 72 6f 67 72 61 6d } //1 EvilProgram
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 49 6e 70 75 74 } //1 TransformInput
		$a_01_3 = {47 65 74 45 6e 63 6f 64 65 64 44 61 74 61 } //1 GetEncodedData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}