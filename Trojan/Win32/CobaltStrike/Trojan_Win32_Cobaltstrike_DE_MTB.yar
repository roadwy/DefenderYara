
rule Trojan_Win32_Cobaltstrike_DE_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 89 c1 03 4d 08 8b 45 f4 03 45 08 0f b6 18 8b 45 f4 89 c2 c1 fa 1f c1 ea 90 01 01 01 d0 83 e0 90 01 01 29 d0 03 45 10 0f b6 00 31 d8 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}