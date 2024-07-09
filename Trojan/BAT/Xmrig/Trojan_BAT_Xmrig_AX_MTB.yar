
rule Trojan_BAT_Xmrig_AX_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 14 0b 14 0c 14 0d 28 ?? ?? ?? 0a 1a 33 0e 72 32 0f 00 70 0c 72 7c 0f 00 70 0d 2b 0c 72 98 0f 00 70 0c 72 e2 0f 00 70 0d 06 08 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Xmrig_AX_MTB_2{
	meta:
		description = "Trojan:BAT/Xmrig.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 2c 1b 2d 1e 26 2b 2d 2b 32 2b 33 72 b5 00 00 70 7e 4c 00 00 0a 2b 2e 2b 33 18 2d 0d 26 dd 56 00 00 00 2b 2f 15 2c f6 2b dc 2b 2b 2b f0 28 ?? ?? ?? 06 2b cd 28 ?? ?? ?? 0a 2b cc 07 2b cb } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 36 00 37 00 } //1 WindowsFormsApp67
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}