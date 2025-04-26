
rule Trojan_Win32_Raccoon_MKQ_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.MKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8b 45 fc f7 f1 8a 0f 8b 45 fc 32 8a 9c 39 41 00 40 88 0c 3e 47 89 45 fc 83 f8 40 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}