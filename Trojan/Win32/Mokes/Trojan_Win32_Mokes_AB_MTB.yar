
rule Trojan_Win32_Mokes_AB_MTB{
	meta:
		description = "Trojan:Win32/Mokes.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 e8 cd 0a ff ff 8d 46 44 50 e8 ca d7 fe ff 33 c0 83 c4 10 88 46 6c 89 46 70 66 89 46 74 88 46 76 8b 44 24 08 89 46 78 8b c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}