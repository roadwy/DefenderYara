
rule Trojan_BAT_Stealer_AYA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 0c 04 00 00 fe 0c 31 00 20 ff ff 1f 00 5f 5a fe 0c 31 00 1f 15 64 58 fe 0e 31 00 20 09 10 01 00 fe 0c 31 00 5a fe 0c 26 00 58 fe 0e 31 00 } //2
		$a_00_1 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //1 Debugger Detected
		$a_01_2 = {24 32 65 65 65 62 66 34 33 2d 31 30 37 33 2d 34 33 31 32 2d 39 64 38 65 2d 65 32 65 36 37 34 36 38 37 66 37 32 } //1 $2eeebf43-1073-4312-9d8e-e2e674687f72
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}