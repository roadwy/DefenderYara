
rule Trojan_BAT_DonutLoader_BA_MTB{
	meta:
		description = "Trojan:BAT/DonutLoader.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {d0 07 00 00 01 28 07 00 00 0a 72 01 00 00 70 17 8d 08 00 00 01 25 16 d0 02 00 00 1b 28 07 00 00 0a a2 28 08 00 00 0a 14 17 8d 04 00 00 01 25 16 28 04 00 00 06 a2 ?? ?? 00 00 0a 2a } //2
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}