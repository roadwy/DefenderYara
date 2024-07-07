
rule Trojan_Win32_Hupigon_RI_MTB{
	meta:
		description = "Trojan:Win32/Hupigon.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 1a 99 59 f7 f9 80 c2 61 88 14 1f 43 3b de 7c ea } //1
		$a_01_1 = {b9 e8 03 00 00 f7 f1 33 d2 b9 80 51 01 00 be 10 0e 00 00 6a 3c 5f 2b 44 24 0c f7 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}