
rule Trojan_BAT_FormBook_MBCN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d d1 } //1
		$a_03_1 = {72 94 0f 00 70 06 72 a8 0f 00 70 6f ?? 00 00 0a 74 ?? 00 00 01 72 ae 0f 00 70 72 4e 0c 00 70 } //1
		$a_01_2 = {50 00 65 00 6e 00 64 00 75 00 6c 00 75 00 6d 00 2e 00 43 00 61 00 6e 00 76 00 61 00 73 00 } //1 Pendulum.Canvas
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}