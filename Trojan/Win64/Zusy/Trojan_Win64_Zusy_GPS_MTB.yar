
rule Trojan_Win64_Zusy_GPS_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 41 8b 30 04 0a 48 ff c1 48 83 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}