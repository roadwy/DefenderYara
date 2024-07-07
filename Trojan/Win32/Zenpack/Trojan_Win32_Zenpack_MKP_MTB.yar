
rule Trojan_Win32_Zenpack_MKP_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f3 81 e3 90 01 04 8b 75 90 01 01 8b 4d 90 01 01 8a 0c 0e 8b 75 90 01 01 32 0c 1e 8b 5d 90 01 01 8b 75 90 01 01 88 0c 33 c7 05 90 01 08 8b 4d 90 01 01 39 cf 8b 4d 90 01 01 89 55 90 01 01 89 4d 90 01 01 89 7d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}