
rule Trojan_Win32_Darkcomet_MBZ_MTB{
	meta:
		description = "Trojan:Win32/Darkcomet.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2f 40 00 b8 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 28 11 40 00 28 11 40 00 e4 10 40 00 78 00 00 00 80 00 00 00 8b 00 00 00 8c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}