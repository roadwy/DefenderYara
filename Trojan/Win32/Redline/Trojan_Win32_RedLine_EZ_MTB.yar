
rule Trojan_Win32_RedLine_EZ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d4 08 ca f6 d0 80 e4 3c 08 ec 30 d4 08 e0 88 04 37 b8 [0-04] 3d [0-04] 0f 8e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}