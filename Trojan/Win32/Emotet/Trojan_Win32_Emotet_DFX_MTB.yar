
rule Trojan_Win32_Emotet_DFX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 14 83 4d fc ff 8a 8c 15 90 01 04 30 08 90 02 04 8d 8d 90 1b 00 89 45 14 90 00 } //1
		$a_81_1 = {6d 6d 5a 59 47 76 47 64 45 32 72 39 68 31 65 79 58 77 43 7a 63 51 31 55 7a 6f 4b 79 74 50 70 38 73 6e 79 36 41 71 59 31 } //1 mmZYGvGdE2r9h1eyXwCzcQ1UzoKytPp8sny6AqY1
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}