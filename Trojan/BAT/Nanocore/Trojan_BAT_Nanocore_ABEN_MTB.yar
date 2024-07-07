
rule Trojan_BAT_Nanocore_ABEN_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0c 07 16 73 19 00 00 0a 73 1a 00 00 0a 0d 09 08 6f 1b 00 00 0a de 0a 09 2c 06 09 6f 1c 00 00 0a dc 08 6f 1d 00 00 0a 13 04 de 14 } //2
		$a_01_1 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}