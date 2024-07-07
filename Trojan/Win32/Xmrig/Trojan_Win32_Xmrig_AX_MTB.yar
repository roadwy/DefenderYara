
rule Trojan_Win32_Xmrig_AX_MTB{
	meta:
		description = "Trojan:Win32/Xmrig.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7b 00 c7 84 24 90 01 04 56 b5 8b 2c c7 84 24 90 01 04 e1 c3 9c 0c c7 84 24 90 01 04 94 27 73 51 c7 84 24 90 01 04 65 48 6d 5a c7 84 24 90 01 04 9f 3a 12 51 c7 84 24 90 01 04 84 82 10 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}