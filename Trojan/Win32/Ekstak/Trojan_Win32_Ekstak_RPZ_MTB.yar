
rule Trojan_Win32_Ekstak_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ec 51 84 00 0e b6 80 00 00 be 0a 00 d4 bd 14 99 a6 79 80 00 00 d4 00 00 20 43 0b 58 } //1
		$a_01_1 = {56 00 42 00 4d 00 61 00 69 00 6c 00 41 00 67 00 65 00 6e 00 74 00 } //1 VBMailAgent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}