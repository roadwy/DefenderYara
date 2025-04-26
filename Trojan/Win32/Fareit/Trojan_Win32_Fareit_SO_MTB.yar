
rule Trojan_Win32_Fareit_SO_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 ff ff 75 f8 5a 30 02 83 45 f8 01 73 05 e8 8a 85 f9 ff 49 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}