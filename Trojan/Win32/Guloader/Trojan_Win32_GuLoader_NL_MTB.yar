
rule Trojan_Win32_GuLoader_NL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 6b 61 74 6b 61 6d 6d 65 72 2e 6f 70 74 } //2 skatkammer.opt
		$a_01_1 = {75 6e 64 65 72 73 6b 72 69 66 74 69 6e 64 73 6d 6c 69 6e 67 65 72 2e 6d 61 6e } //2 underskriftindsmlinger.man
		$a_01_2 = {4e 6f 6e 73 75 63 63 6f 75 72 2e 77 68 69 } //1 Nonsuccour.whi
		$a_01_3 = {45 6c 6f 6b 76 65 6e 74 2e 68 61 6c } //1 Elokvent.hal
		$a_01_4 = {46 6f 72 67 72 69 6e 67 2e 73 61 6d } //1 Forgring.sam
		$a_01_5 = {62 6c 6f 6d 6d 65 68 61 76 65 } //1 blommehave
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}