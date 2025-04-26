
rule Trojan_Win32_Glupteba_MBKI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MBKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 00 6f 00 64 00 65 00 68 00 6f 00 6c 00 6f 00 66 00 61 00 66 00 75 00 79 00 00 00 7a 75 62 61 73 6f 00 00 6b 65 67 75 64 69 74 61 78 75 } //1
		$a_01_1 = {65 00 62 00 6f 00 7a 00 75 00 62 00 6f 00 64 00 00 00 6e 00 69 00 67 00 6f 00 63 } //1
		$a_81_2 = {67 69 78 61 6d 6f 68 65 73 6f 62 75 62 6f 64 65 68 6f 6c 6f 66 61 66 75 79 } //1 gixamohesobubodeholofafuy
		$a_81_3 = {76 61 79 65 68 69 7a 65 70 6f 76 69 66 69 } //1 vayehizepovifi
		$a_81_4 = {6a 75 79 6f 6a 65 77 69 70 69 68 65 68 69 79 6f 78 69 79 65 6e 65 78 65 67 69 74 6f 6d } //1 juyojewipihehiyoxiyenexegitom
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}