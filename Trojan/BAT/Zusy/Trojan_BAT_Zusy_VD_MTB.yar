
rule Trojan_BAT_Zusy_VD_MTB{
	meta:
		description = "Trojan:BAT/Zusy.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 75 62 20 53 65 61 72 63 68 43 6f 6e 74 61 63 74 } //2 Sub SearchContact
		$a_81_1 = {63 73 63 72 69 70 74 2e 65 78 65 } //2 cscript.exe
		$a_81_2 = {2f 2f 42 20 2f 2f 4e 6f 6c 6f 67 6f 20 2f 2f 45 3a 56 42 53 63 72 69 70 74 20 } //2 //B //Nologo //E:VBScript 
		$a_81_3 = {54 65 6d 70 56 61 6c 75 65 20 3d 20 52 69 67 68 74 28 22 69 6e 76 66 69 73 69 62 6c 65 22 2c 20 33 29 } //2 TempValue = Right("invfisible", 3)
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 28 22 65 63 64 73 66 68 6f 22 29 } //2 StrReverse("ecdsfho")
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2) >=10
 
}