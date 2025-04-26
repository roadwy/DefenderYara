
rule Trojan_BAT_Vahodon_C{
	meta:
		description = "Trojan:BAT/Vahodon.C,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {6e 00 6a 00 2d 00 71 00 38 00 } //10 nj-q8
		$a_00_1 = {69 00 6e 00 66 00 6f 00 7c 00 7c 00 6d 00 79 00 49 00 44 00 7c 00 7c 00 } //1 info||myID||
		$a_00_2 = {6f 00 70 00 65 00 6e 00 75 00 72 00 6c 00 } //1 openurl
		$a_00_3 = {73 00 65 00 6e 00 64 00 66 00 69 00 6c 00 65 00 } //1 sendfile
		$a_01_4 = {6b 6f 6e 65 6b } //1 konek
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}