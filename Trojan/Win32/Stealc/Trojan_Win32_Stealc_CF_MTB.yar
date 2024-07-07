
rule Trojan_Win32_Stealc_CF_MTB{
	meta:
		description = "Trojan:Win32/Stealc.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 37 8a 80 90 01 04 0f be 5c 37 01 8a 9b 08 f8 40 00 c0 eb 90 01 01 c0 e0 90 01 01 0a c3 88 01 90 00 } //5
		$a_03_1 = {0f be 44 37 02 0f be 5c 37 01 8a 9b 90 01 04 8a 80 90 01 04 c0 e3 90 01 01 c0 e8 90 01 01 0a c3 88 41 01 90 00 } //5
		$a_03_2 = {0f be 5c 37 02 0f be 44 37 03 8a 9b 08 f8 40 00 c0 e3 90 01 01 0a 90 01 05 83 c6 90 01 01 88 59 02 83 c1 90 01 01 3b 75 08 7c 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}