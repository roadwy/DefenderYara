
rule Trojan_Win32_Barys_AB_MTB{
	meta:
		description = "Trojan:Win32/Barys.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5b b8 13 8d ff ff 80 34 03 b8 40 3d d6 fa ff ff 75 f4 61 e9 76 ?? ff ff 60 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}