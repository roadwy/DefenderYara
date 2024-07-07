
rule Trojan_Win32_Amadey_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 d8 89 45 fc 33 45 e8 31 45 f8 8b 45 f0 89 45 e0 8b 45 f8 29 45 e0 8b 45 e0 89 45 f0 8b 45 c4 29 45 f4 ff 4d d4 0f 85 90 01 04 8b 45 f0 5e 89 07 89 57 04 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}