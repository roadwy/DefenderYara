
rule Trojan_Win32_Azorult_RS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea c7 05 90 01 04 2e ce 50 91 89 90 01 02 8b 90 01 02 01 90 01 02 83 90 01 05 67 75 90 00 } //1
		$a_03_1 = {33 cb 33 4d 90 01 01 8d 90 01 02 89 90 01 02 e8 90 01 04 89 90 01 02 25 1b 07 d0 4d 81 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}