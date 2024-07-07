
rule Trojan_Win32_Azorult_OF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.OF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 39 1d 90 02 06 8b 90 02 05 8b 90 02 05 8a 90 02 06 8b 90 02 05 88 90 02 02 81 3d 90 02 08 75 90 00 } //1
		$a_02_1 = {33 f6 39 1d 90 02 04 90 18 e8 90 02 04 e8 90 02 04 8b 90 02 05 8b 90 02 05 33 f6 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}