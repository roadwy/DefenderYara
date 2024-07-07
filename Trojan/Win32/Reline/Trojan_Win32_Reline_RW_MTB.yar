
rule Trojan_Win32_Reline_RW_MTB{
	meta:
		description = "Trojan:Win32/Reline.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c3 8b 45 90 01 01 09 d9 88 08 b8 e0 6b 7a 96 3d c4 1f 36 d7 7f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}