
rule Trojan_Win32_Gozi_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 18 03 c6 03 c7 83 c4 04 47 88 3c 08 3b 7c 24 10 0f 82 f2 fe ff ff ff 54 24 14 5f 5e 33 c0 5b 8b e5 5d c2 10 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}