
rule Ransom_MSIL_Ransim_MEL_MTB{
	meta:
		description = "Ransom:MSIL/Ransim.MEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 70 71 71 63 69 66 79 20 74 68 71 71 20 2d 71 71 78 74 72 61 63 74 } //1 spqqcify thqq -qqxtract
		$a_81_1 = {50 43 4d 4e 43 69 35 54 57 55 35 50 55 46 4e 4a 55 77 30 4b 49 43 41 67 55 6d 56 73 5a 57 46 7a 5a 54 6f 67 51 6d 56 68 64 58 67 4e 43 69 41 67 49 46 4a 68 62 } //1 PCMNCi5TWU5PUFNJUw0KICAgUmVsZWFzZTogQmVhdXgNCiAgIFJhb
		$a_81_2 = {52 75 62 72 69 6b 52 61 6e 53 69 6d } //1 RubrikRanSim
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}