
rule Trojan_Win32_Azorult_XT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.XT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 69 88 0d 90 01 04 c7 05 90 01 04 50 72 6f 74 c7 05 90 01 04 65 63 74 00 c7 05 90 01 04 74 75 61 6c ff 15 90 01 04 a3 90 0a 3d 00 50 a3 90 01 04 66 c7 05 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}