
rule Trojan_Win32_Ramsay_DA_MTB{
	meta:
		description = "Trojan:Win32/Ramsay.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 b9 1a 00 00 00 f7 f1 89 55 f4 0f b7 55 f4 83 c2 61 66 89 55 fc 8b 45 f0 8b 4d f8 66 8b 55 fc 66 89 14 41 6a 0a ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}