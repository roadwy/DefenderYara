
rule Trojan_Win32_Amadey_IP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.IP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 33 8d 4d c8 32 06 88 45 ff 8d 45 ff 6a 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}