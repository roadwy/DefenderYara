
rule Trojan_Win32_Azorult_NQ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 3b 83 90 02 03 90 18 47 3b 7d 08 90 18 81 7d 90 02 05 90 18 90 18 a1 90 02 04 69 90 02 05 05 90 02 04 a3 90 02 04 0f 90 02 06 25 90 02 04 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}