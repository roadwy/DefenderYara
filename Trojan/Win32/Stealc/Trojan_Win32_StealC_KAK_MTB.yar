
rule Trojan_Win32_StealC_KAK_MTB{
	meta:
		description = "Trojan:Win32/StealC.KAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 f3 81 c3 ac 4e 6e 7d 31 03 8b 1c 24 83 c4 04 51 } //1
		$a_01_1 = {51 50 c7 04 24 00 00 00 00 59 01 f1 31 01 59 50 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}