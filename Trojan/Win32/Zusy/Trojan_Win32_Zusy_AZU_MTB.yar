
rule Trojan_Win32_Zusy_AZU_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 c1 e8 18 89 4e 06 0f b6 0c 85 20 5d 5f 00 0f b6 46 0b 8b 0c 8d 20 51 5f 00 0f b6 04 85 20 5d 5f 00 33 0c 85 20 49 5f 00 0f b6 46 0c 0f b6 04 85 20 5d 5f 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}