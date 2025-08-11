
rule Trojan_Win32_GuLoader_RAX_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 6b 72 69 6e 67 6c 65 72 6e 65 73 5c 6c 75 6d 62 65 72 6a 61 63 6b 73 } //1 \kringlernes\lumberjacks
		$a_81_1 = {69 73 6d 65 6a 65 72 69 5c 63 6f 72 64 79 6c 61 6e 74 68 75 73 5c 73 75 70 70 6f 73 65 } //1 ismejeri\cordylanthus\suppose
		$a_81_2 = {25 74 61 62 65 72 73 25 5c 61 66 6d 6f 6e 74 65 72 65 72 5c 64 69 6c 6c 65 72 64 61 6c 6c 65 72 } //1 %tabers%\afmonterer\dillerdaller
		$a_81_3 = {5c 53 70 72 6f 67 62 72 75 67 65 72 6e 65 5c 65 6e 65 72 6e 65 2e 74 78 74 } //1 \Sprogbrugerne\enerne.txt
		$a_81_4 = {62 75 67 67 79 6d 65 6e 20 63 6f 76 65 72 63 68 69 65 66 20 62 65 73 6f 74 74 69 6e 67 } //1 buggymen coverchief besotting
		$a_81_5 = {6b 6f 72 72 6f 64 65 72 } //1 korroder
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}