
rule Trojan_Win32_Chapak_MR_MTB{
	meta:
		description = "Trojan:Win32/Chapak.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f7 c1 e6 90 01 01 81 3d 90 02 08 90 18 90 02 02 c1 e8 90 01 01 89 90 02 03 8b 90 02 03 01 90 02 05 8d 90 02 02 33 90 01 01 81 90 02 09 c7 90 02 09 90 18 31 90 02 03 81 3d 90 02 08 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}