
rule Trojan_Win32_Emotet_PSY_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 ?? 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 ?? 83 c4 ?? 8a 4c 14 ?? 30 08 } //1
		$a_81_1 = {30 4e 48 36 4e 4e 47 43 64 79 70 74 7a 4c 4f 41 51 39 69 50 43 32 5a 4d 36 53 4b 44 4f 72 69 57 41 57 49 6a 39 } //1 0NH6NNGCdyptzLOAQ9iPC2ZM6SKDOriWAWIj9
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}