
rule Trojan_Win32_Zusy_AMAC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 8d bc 24 90 01 04 03 fb 0f b6 07 03 c6 25 90 01 04 79 07 48 0d 90 01 04 40 8d b4 24 90 01 04 89 44 24 10 03 f0 56 57 e8 90 01 04 0f b6 06 83 c4 08 0f b6 0f 8b 74 24 10 03 c8 0f b6 c1 8a 84 04 90 01 04 30 85 90 01 04 45 81 fd 90 01 04 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}