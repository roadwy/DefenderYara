
rule Trojan_BAT_Zemsil_SG_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 72 31 2e 65 78 65 } //2 server1.exe
		$a_01_1 = {32 30 32 34 20 44 69 73 70 6c 61 79 20 44 72 69 76 65 72 } //2 2024 Display Driver
		$a_01_2 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 37 38 33 39 32 } //2 $cc7fad03-816e-432c-9b92-001f2d378392
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}