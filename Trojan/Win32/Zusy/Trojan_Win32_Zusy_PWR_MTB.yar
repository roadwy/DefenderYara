
rule Trojan_Win32_Zusy_PWR_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 8b 75 10 8b c1 83 e0 1f 8a 04 30 30 04 0a 41 3b 4d 0c 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}