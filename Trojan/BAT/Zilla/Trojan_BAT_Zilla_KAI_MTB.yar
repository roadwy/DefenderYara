
rule Trojan_BAT_Zilla_KAI_MTB{
	meta:
		description = "Trojan:BAT/Zilla.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 43 00 3a 00 5c 00 46 00 79 00 00 15 5c 00 66 00 79 00 5f 00 6c 00 2e 00 64 00 61 00 74 00 61 } //1
		$a_01_1 = {46 79 2e 45 78 65 } //1 Fy.Exe
		$a_01_2 = {66 79 50 61 74 68 } //1 fyPath
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}