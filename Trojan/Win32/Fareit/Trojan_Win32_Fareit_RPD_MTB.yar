
rule Trojan_Win32_Fareit_RPD_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 3d 5a 42 87 da 43 49 6a 3c 5b 8d 98 19 02 00 00 50 59 69 c9 01 03 00 00 6a 00 6a 01 8b 45 e4 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}