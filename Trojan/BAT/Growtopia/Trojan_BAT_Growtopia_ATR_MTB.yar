
rule Trojan_BAT_Growtopia_ATR_MTB{
	meta:
		description = "Trojan:BAT/Growtopia.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 05 00 00 "
		
	strings :
		$a_02_0 = {0b 2b 13 07 08 72 90 01 03 70 6f 90 01 03 0a 58 6f 90 01 03 0a 0b 07 72 90 01 03 70 6f 90 01 03 0a 25 0c 15 33 dd 90 00 } //10
		$a_80_1 = {68 74 74 70 73 3a 5c 5c 5c 2f 5c 5c 5c 2f 69 2e 69 62 62 2e 63 6f 5c 5c 5c 2f 5b 41 2d 7a 30 2d 39 5d 2b 5c 2f 5b 41 2d 7a 30 2d 39 5d 2b 2e 6a 70 67 } //https:\\\/\\\/i.ibb.co\\\/[A-z0-9]+\/[A-z0-9]+.jpg  5
		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  4
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 47 72 6f 77 74 6f 70 69 61 } //SOFTWARE\Growtopia  4
		$a_80_4 = {44 69 73 63 6f 72 64 } //Discord  4
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4) >=12
 
}