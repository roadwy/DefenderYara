
rule Trojan_BAT_AgentTesla_NEAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_01_0 = {18 8d 17 00 00 01 25 16 72 57 55 02 70 a2 25 17 72 d7 01 00 70 a2 14 14 14 28 18 02 00 0a 28 ab 01 00 0a 0b 07 0a 2b 00 06 2a } //10
		$a_01_1 = {64 00 6c 00 2e 00 64 00 72 00 6f 00 70 00 62 00 6f 00 78 00 2e 00 63 00 6f 00 6d 00 } //5 dl.dropbox.com
		$a_01_2 = {68 00 69 00 64 00 65 00 2e 00 62 00 61 00 74 00 } //2 hide.bat
		$a_01_3 = {73 00 68 00 6f 00 77 00 2e 00 62 00 61 00 74 00 } //2 show.bat
		$a_01_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
		$a_01_5 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //1 Replace
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=21
 
}