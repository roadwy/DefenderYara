
rule Trojan_BAT_RedLine_MBWC_MTB{
	meta:
		description = "Trojan:BAT/RedLine.MBWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 37 33 66 31 77 77 51 47 36 00 4b 6d 39 4c 53 6f 44 6b 61 47 66 37 66 4c 4a 4c 77 71 66 00 42 67 30 63 63 55 44 68 75 62 31 44 } //2
		$a_01_1 = {69 6e 73 74 72 75 63 74 69 6f 6e 5f 6d 61 6e 75 61 6c 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 } //1 instruction_manual.Resources.resourc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}