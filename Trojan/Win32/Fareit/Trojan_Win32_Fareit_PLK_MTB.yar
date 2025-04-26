
rule Trojan_Win32_Fareit_PLK_MTB{
	meta:
		description = "Trojan:Win32/Fareit.PLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a d8 8a d0 24 f0 c0 e3 06 0a 5c 0f 02 c0 e0 02 0a 04 0f 80 e2 fc c0 e2 04 0a 54 0f 01 88 5d ff 8b 5d f8 88 04 1e 8a 45 ff 46 88 14 1e 46 88 04 1e 8b 45 0c 83 c1 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}