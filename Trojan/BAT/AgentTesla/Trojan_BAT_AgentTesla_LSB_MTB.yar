
rule Trojan_BAT_AgentTesla_LSB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {66 73 68 64 66 68 6b 68 66 66 66 64 66 64 66 61 66 61 73 72 64 61 64 73 61 74 72 66 66 66 66 66 66 66 66 66 64 64 66 } //1 fshdfhkhfffdfdfafasrdadsatrfffffffffddf
		$a_01_1 = {6d 79 6e 61 6d 65 73 70 76 76 76 76 76 76 76 76 76 76 76 76 76 76 76 61 63 65 } //1 mynamespvvvvvvvvvvvvvvvace
		$a_01_2 = {66 73 64 73 64 66 6b 68 6b 68 73 66 64 66 64 61 64 64 64 64 67 61 61 61 61 61 64 77 72 65 65 65 67 66 73 64 66 } //1 fsdsdfkhkhsfdfdaddddgaaaaadwreeegfsdf
		$a_01_3 = {4d 61 63 63 63 63 63 63 63 69 6e } //1 Macccccccin
		$a_01_4 = {23 66 6b 61 73 64 66 67 66 66 67 73 66 66 66 73 64 2e 64 6c 6c 23 } //1 #fkasdfgffgsfffsd.dll#
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}