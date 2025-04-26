
rule Trojan_BAT_AgentTesla_MI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fe 0c 02 00 20 ?? ?? ?? ?? fe 01 39 27 00 00 00 20 23 00 00 00 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 02 00 00 00 fe 0e 02 00 } //1
		$a_01_1 = {2f 00 6f 00 70 00 74 00 69 00 6d 00 69 00 7a 00 65 00 2b 00 20 00 2f 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 3a 00 58 00 38 00 36 00 20 00 2f 00 74 00 61 00 72 00 67 00 65 00 74 00 3a 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 } //1 /optimize+ /platform:X86 /target:library
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 00 70 00 6c 00 6f 00 6f 00 64 00 65 00 72 00 2e 00 6e 00 65 00 74 00 2f 00 69 00 6d 00 67 00 2f 00 69 00 6d 00 61 00 67 00 65 00 } //1 uplooder.net/img/image
		$a_01_1 = {47 00 65 00 74 00 42 00 79 00 74 00 65 00 41 00 72 00 72 00 61 00 79 00 41 00 73 00 79 00 6e 00 63 00 } //1 GetByteArrayAsync
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}