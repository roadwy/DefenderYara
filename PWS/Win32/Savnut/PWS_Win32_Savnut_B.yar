
rule PWS_Win32_Savnut_B{
	meta:
		description = "PWS:Win32/Savnut.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 73 6e 65 74 62 61 6e 6b 65 5f 25 73 5f 25 73 } //1 %snetbanke_%s_%s
		$a_01_1 = {2a 78 69 74 69 5b 2a } //1 *xiti[*
		$a_01_2 = {26 63 68 65 63 6b 3d 63 68 63 6b } //1 &check=chck
		$a_01_3 = {81 3f 6e 6f 6e 65 74 } //2
		$a_01_4 = {c7 07 55 53 46 3d af 33 c0 } //2
		$a_01_5 = {b8 47 00 00 00 ba 6f 6f 67 6c b9 fc 0f 00 00 f2 ae } //2
		$a_01_6 = {ac aa 3c 40 75 fa 8b d7 8b 7d e8 8b cf b8 0a 00 00 00 f2 ae } //2
		$a_01_7 = {85 c0 74 08 8b 45 fc 80 38 40 75 0e ff 75 f0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=5
 
}