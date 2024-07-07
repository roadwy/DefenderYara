
rule Trojan_Win32_Glupteba_MBJV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {a1 dc 4a fa 02 8a 84 30 4b 13 01 00 8b 0d 2c 3a fa 02 88 04 31 75 } //2
		$a_81_1 = {6c 61 68 61 6e 65 6b 75 63 6f 66 69 6a 61 6a 69 77 61 77 } //1 lahanekucofijajiwaw
		$a_81_2 = {73 65 77 6f 6d 65 78 69 6b 69 6a 61 6c 6f 64 65 64 65 6c 65 76 65 20 73 6f 79 75 67 6f 6c 6f 72 61 63 69 20 79 61 6d 61 7a 69 64 } //1 sewomexikijalodedeleve soyugoloraci yamazid
		$a_81_3 = {72 75 6a 65 68 75 6c 61 79 61 66 61 6c 69 67 75 62 6f 76 6f 74 6f 64 65 68 6f } //1 rujehulayafaligubovotodeho
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}