
rule Trojan_Win32_Zusy_AP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 e5 d7 59 4b 19 83 0c 87 46 81 30 8e bf 0b e9 b0 3c 14 70 e3 ee 48 4c 7e 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}