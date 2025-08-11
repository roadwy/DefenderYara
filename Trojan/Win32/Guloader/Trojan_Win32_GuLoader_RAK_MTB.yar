
rule Trojan_Win32_GuLoader_RAK_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 68 69 6e 73 6b 65 73 5c 54 65 72 72 6f 72 72 65 67 69 6d 65 6e 74 65 72 6e 65 73 } //1 rhinskes\Terrorregimenternes
		$a_81_1 = {62 6f 72 65 74 61 61 72 6e 65 74 73 5c 6d 79 6f 73 65 72 73 } //1 boretaarnets\myosers
		$a_81_2 = {25 6d 61 72 65 72 69 64 74 25 5c 61 74 65 73 74 69 6e 65 2e 62 69 6e } //1 %mareridt%\atestine.bin
		$a_81_3 = {68 76 61 72 72 65 20 73 6c 61 67 74 65 74 69 64 65 72 6e 65 20 63 6c 75 73 69 61 63 65 6f 75 73 } //1 hvarre slagtetiderne clusiaceous
		$a_81_4 = {75 6e 68 6f 73 70 69 74 61 6c 20 68 79 64 72 6f 6c 6f 67 69 73 6b 2e 65 78 65 } //1 unhospital hydrologisk.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}