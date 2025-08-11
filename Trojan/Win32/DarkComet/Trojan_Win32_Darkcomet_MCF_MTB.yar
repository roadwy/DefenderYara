
rule Trojan_Win32_Darkcomet_MCF_MTB{
	meta:
		description = "Trojan:Win32/Darkcomet.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d8 48 40 00 d4 11 40 00 10 f2 70 00 00 ff ff ff 08 00 00 00 01 00 00 00 0c 00 00 00 e9 00 00 00 7c 33 40 00 08 11 40 00 c4 10 40 00 78 00 00 00 7e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}