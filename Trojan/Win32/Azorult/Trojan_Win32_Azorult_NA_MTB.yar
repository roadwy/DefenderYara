
rule Trojan_Win32_Azorult_NA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 04 3b 83 90 02 03 90 18 47 3b 90 02 02 90 18 90 18 a1 90 02 04 69 90 02 05 05 90 02 04 a3 90 02 04 0f 90 02 06 25 90 02 04 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_NA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.NA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 7d ec 10 8d 4d d8 8b c3 8b b7 0c 01 00 00 0f 43 4d d8 33 d2 f7 75 e8 8a 04 0a 30 04 1e 43 8b 87 10 01 00 00 2b 87 0c 01 00 00 3b d8 75 d1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}