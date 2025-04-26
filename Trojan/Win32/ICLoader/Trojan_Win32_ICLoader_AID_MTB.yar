
rule Trojan_Win32_ICLoader_AID_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.AID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0d 4a 10 8a 00 8a 15 4d 10 8a 00 a1 34 10 8a 00 22 d1 8b 0d 30 10 8a 00 88 15 4d 10 8a 00 8b d0 6a 10 c1 ea 02 2b ca 33 d2 8a 15 43 10 8a 00 89 0d 30 10 8a 00 8b 0d 38 10 8a 00 83 c9 07 0f af ca 23 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}