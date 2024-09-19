
rule Trojan_Win64_Zusy_AMAA_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 ff e8 ?? ?? ?? ?? b9 1a 00 00 00 99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 fe e8 ?? ?? ?? ?? b9 1a 00 00 00 99 f7 f9 83 c2 61 c1 e2 18 c1 fa 18 88 55 fd e8 } //2
		$a_80_1 = {76 35 2e 6d 72 6d 70 7a 6a 6a 68 6e 33 73 67 74 71 35 77 2e 70 72 6f } //v5.mrmpzjjhn3sgtq5w.pro  2
		$a_80_2 = {69 73 61 70 69 2f 69 73 61 70 69 76 35 2e 64 6c 6c 2f 76 35 } //isapi/isapiv5.dll/v5  1
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}