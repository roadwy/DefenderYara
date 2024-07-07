
rule Trojan_BAT_FormBook_ADQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 49 00 16 0d 2b 31 00 07 08 09 28 } //2
		$a_01_1 = {44 00 43 00 50 00 55 00 56 00 4d 00 } //1 DCPUVM
		$a_01_2 = {55 59 52 30 30 31 30 34 35 33 } //1 UYR0010453
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}