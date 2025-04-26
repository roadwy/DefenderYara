
rule Trojan_BAT_Nanocore_ABD_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b 07 02 08 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 0d 08 09 58 0c 09 20 ?? ?? ?? 00 2f d8 0f 00 08 28 ?? ?? ?? 2b 07 6f ?? ?? ?? 0a dd ?? ?? ?? 00 07 39 ?? ?? ?? 00 07 6f ?? ?? ?? 0a dc 90 0a 48 00 0f 00 08 20 ?? ?? ?? 00 58 28 01 } //2
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_3 = {43 6f 6e 74 72 6f 6c 44 6f 6d 61 69 6e 50 6f 6c 69 63 79 } //1 ControlDomainPolicy
		$a_01_4 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}