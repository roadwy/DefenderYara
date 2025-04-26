
rule Trojan_BAT_Remcos_A_MTB{
	meta:
		description = "Trojan:BAT/Remcos.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 72 0f 00 00 70 6f 1c 00 00 0a 14 17 8d 01 00 00 01 25 16 02 a2 28 22 00 00 06 2a } //2
		$a_01_1 = {7e 02 00 00 04 2d 1e 72 21 00 00 70 d0 0b 00 00 02 28 3f 00 00 06 6f 32 00 00 0a 73 33 00 00 0a 80 02 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Remcos_A_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //1 RPF:SmartAssembly
		$a_01_1 = {6e 68 66 66 73 6b 64 73 66 6b 64 64 64 66 64 68 64 61 66 66 66 64 64 64 66 64 64 64 68 67 66 73 64 73 63 66 66 64 66 } //1 nhffskdsfkdddfdhdafffdddfdddhgfsdscffdf
		$a_01_2 = {68 6b 67 66 73 66 64 66 66 64 68 66 68 64 64 66 64 72 66 61 68 67 68 64 64 73 73 68 63 66 } //1 hkgfsfdffdhfhddfdrfahghddsshcf
		$a_01_3 = {63 68 66 64 64 67 65 66 66 66 67 68 6b 64 61 66 66 73 66 68 64 64 64 68 64 73 68 64 67 68 66 } //1 chfddgefffghkdaffsfhdddhdshdghf
		$a_01_4 = {73 64 64 64 64 66 66 73 66 68 65 67 68 64 64 6a 66 66 66 66 66 67 6a 68 73 6b 64 67 67 73 66 61 61 66 63 73 61 66 70 } //1 sddddffsfheghddjfffffgjhskdggsfaafcsafp
		$a_01_5 = {73 66 68 6a 66 66 6b 66 68 67 66 64 6a 73 72 66 68 68 64 64 66 68 66 66 66 61 64 73 67 66 61 73 66 68 73 73 63 66 66 67 64 62 } //1 sfhjffkfhgfdjsrfhhddfhfffadsgfasfhsscffgdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}