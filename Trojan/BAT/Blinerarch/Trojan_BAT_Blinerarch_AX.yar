
rule Trojan_BAT_Blinerarch_AX{
	meta:
		description = "Trojan:BAT/Blinerarch.AX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {40 00 61 00 73 00 64 00 61 00 73 00 64 00 2e 00 72 00 75 00 } //1 @asdasd.ru
		$a_00_1 = {76 69 70 70 72 69 63 65 00 } //1
		$a_00_2 = {73 6d 73 63 6f 75 6e 74 } //1 smscount
		$a_03_3 = {76 69 70 5f 70 61 74 74 65 72 6e 00 90 09 14 00 70 61 74 74 65 72 6e 00 75 72 6c 5f } //1
		$a_03_4 = {0d 63 00 50 00 68 00 6f 00 6e 00 65 00 00 90 08 55 00 63 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 90 08 e0 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //2
		$a_02_5 = {63 00 69 00 5f 00 73 00 65 00 73 00 73 00 69 00 6f 00 6e 00 3d 00 28 00 5b 00 5e 00 3b 00 5d 00 2b 00 29 00 90 0a 60 00 73 00 65 00 6e 00 64 00 5f 00 73 00 [0-1f] 65 00 6d 00 61 00 69 00 6c 00 00 [0-1f] 70 00 68 00 6f 00 6e 00 65 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_02_5  & 1)*2) >=6
 
}