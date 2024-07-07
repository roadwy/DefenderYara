
rule Trojan_Win32_Letikro_B{
	meta:
		description = "Trojan:Win32/Letikro.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 55 44 50 5c 63 } //2 SOFTWARE\Microsoft\UDP\c
		$a_01_1 = {2f 21 72 61 6a 2e 72 6f 72 72 65 3a 72 61 6a } //2 /!raj.rorre:raj
		$a_01_2 = {6c 75 78 2e 73 6d 72 6f 66 6b 6f 6f 68 6d 2f 74 6e 65 74 6e 6f 63 2f 73 6d 72 6f 66 6b 6f 6f 68 6d 2f 2f 3a 65 6d 6f 72 68 63 } //2 lux.smrofkoohm/tnetnoc/smrofkoohm//:emorhc
		$a_00_3 = {4d 00 69 00 6d 00 69 00 63 00 6b 00 65 00 72 00 2c 00 20 00 46 00 53 00 42 00 2d 00 50 00 4f 00 57 00 45 00 52 00 20 00 32 00 30 00 30 00 38 00 2d 00 39 00 } //3 Mimicker, FSB-POWER 2008-9
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_00_3  & 1)*3) >=5
 
}