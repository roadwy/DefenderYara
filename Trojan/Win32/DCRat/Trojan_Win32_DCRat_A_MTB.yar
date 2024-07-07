
rule Trojan_Win32_DCRat_A_MTB{
	meta:
		description = "Trojan:Win32/DCRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 c8 aa fe ff c1 e0 90 01 01 8d 8d f8 aa fe ff 0f b6 14 08 f7 da 8b 85 c8 aa fe ff c1 e0 90 01 01 8d 8d f8 aa fe ff 88 14 08 eb 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}