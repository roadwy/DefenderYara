
rule Trojan_Win32_Farfli_ASDM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c8 33 d1 8b 4d 08 03 4d f8 } //5
		$a_01_1 = {6a 04 68 00 20 00 00 8b 45 d0 8b 48 50 51 8b 55 d0 8b 42 34 50 ff 15 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}