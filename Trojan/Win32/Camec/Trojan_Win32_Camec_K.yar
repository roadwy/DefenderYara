
rule Trojan_Win32_Camec_K{
	meta:
		description = "Trojan:Win32/Camec.K,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 5f 43 6f 6e 76 65 72 74 58 54 6f 44 56 44 } //1 F_ConvertXToDVD
		$a_01_1 = {54 5f 45 6d 70 72 65 73 61 72 69 6f } //1 T_Empresario
		$a_01_2 = {46 75 6e 63 5f 52 61 7a 61 6f } //1 Func_Razao
		$a_01_3 = {55 47 54 5f 44 65 63 69 6f } //1 UGT_Decio
		$a_03_4 = {66 3b f3 0f 8c 90 01 01 00 00 00 66 6b ff 40 66 8b 45 dc 0f 80 90 01 01 01 00 00 66 03 fe 0f 80 90 01 01 01 00 00 66 05 06 00 0f 80 90 01 01 01 00 00 66 3d 08 00 89 45 dc 0f 8c 90 01 01 00 00 00 0f bf f7 8d 55 dc 66 2d 08 00 90 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*10) >=13
 
}