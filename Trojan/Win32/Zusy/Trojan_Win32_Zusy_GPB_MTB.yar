
rule Trojan_Win32_Zusy_GPB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 7d 5f 00 d4 75 5f 00 98 7d 5f 00 bc 7d 5f 00 20 7d 5f 00 48 7d 5f 00 88 7d 5f 00 aa 7d 5f 00 cc 7d 5f 00 74 7d 5f 00 36 7d 5f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}