
rule Trojan_Win32_Zusy_AQ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 33 ca 42 03 1d 41 5f 53 00 87 c1 87 c1 4a 33 ca 43 21 0d 3d 5c 53 00 81 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}