
rule Trojan_Win32_Smokeloader_GAN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {6c 6f 79 75 73 6f 74 6f 6e 6f 66 61 73 75 62 61 } //loyusotonofasuba  2
		$a_80_1 = {6a 6f 6b 65 64 69 74 65 72 6f 76 69 77 65 64 61 72 61 66 69 6e 61 79 6f 67 } //jokediteroviwedarafinayog  2
		$a_80_2 = {6a 6f 77 75 68 61 72 61 74 61 70 69 79 69 6c 69 6a 61 64 65 7a 75 6d 61 64 61 79 65 64 75 6a 65 } //jowuharatapiyilijadezumadayeduje  2
		$a_80_3 = {62 69 6b 6f 76 65 68 6f 6c 61 6a 69 6a 6f 76 69 7a 69 6a 69 6c 75 6d 65 66 75 } //bikoveholajijovizijilumefu  2
		$a_01_4 = {6a 69 72 69 79 61 6d 75 77 65 7a } //2 jiriyamuwez
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}