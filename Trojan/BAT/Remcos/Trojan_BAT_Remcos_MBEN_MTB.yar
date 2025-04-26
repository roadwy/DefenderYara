
rule Trojan_BAT_Remcos_MBEN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MBEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 64 64 64 66 66 68 65 64 66 64 64 66 66 66 66 67 6a 66 73 66 6b 64 67 73 61 63 73 61 66 70 } //1 sdddffhedfddffffgjfsfkdgsacsafp
		$a_01_1 = {73 67 66 68 6a 66 66 66 67 64 72 66 68 64 64 66 68 66 66 66 61 64 66 73 66 73 73 63 66 67 64 62 } //1 sgfhjfffgdrfhddfhfffadfsfsscfgdb
		$a_01_2 = {64 6a 66 73 66 68 67 64 66 66 61 66 63 66 64 73 73 66 6b 66 68 67 6a } //1 djfsfhgdffafcfdssfkfhgj
		$a_01_3 = {66 66 63 68 6b 66 66 64 61 68 66 64 73 66 73 66 6a } //1 ffchkffdahfdsfsfj
		$a_01_4 = {6a 68 66 64 66 66 64 66 64 68 } //1 jhfdffdfdh
		$a_01_5 = {66 64 66 63 66 66 72 64 67 66 64 66 73 66 73 66 66 6a } //1 fdfcffrdgfdfsfsffj
		$a_01_6 = {6a 66 66 66 66 67 66 64 73 64 66 6b 73 64 67 6b 66 66 66 66 } //1 jffffgfdsdfksdgkffff
		$a_01_7 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}