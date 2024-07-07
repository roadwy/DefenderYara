
rule Trojan_Win32_Azorult_EAN_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 05 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 0c 02 8b 0d 90 01 04 81 f9 03 02 00 00 75 0a c7 05 90 01 04 74 19 00 00 40 3b c1 72 d0 90 00 } //10
		$a_00_1 = {30 04 3b 83 7d 08 19 75 1c 56 } //5
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*5) >=5
 
}