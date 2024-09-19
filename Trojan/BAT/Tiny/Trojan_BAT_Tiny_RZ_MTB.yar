
rule Trojan_BAT_Tiny_RZ_MTB{
	meta:
		description = "Trojan:BAT/Tiny.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 2a 11 05 17 58 13 05 11 05 11 04 8e 69 32 bd 08 17 58 0c 08 07 8e 69 32 a7 16 2a } //1
		$a_01_1 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 20 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 } //1 windows explorer tracker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}