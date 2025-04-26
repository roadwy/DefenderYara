
rule Trojan_BAT_AsyncRAT_MBAT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 11 04 72 ff 00 00 70 15 16 28 ?? 00 00 0a 0d de 16 } //1
		$a_01_1 = {78 34 34 54 51 32 44 72 43 65 77 52 48 76 32 } //1 x44TQ2DrCewRHv2
		$a_01_2 = {6e 6f 6c 61 6e 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 nolane.Resources.resources
		$a_01_3 = {31 30 31 62 36 62 32 35 31 35 } //1 101b6b2515
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}