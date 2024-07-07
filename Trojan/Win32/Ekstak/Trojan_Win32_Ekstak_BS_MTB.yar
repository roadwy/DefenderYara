
rule Trojan_Win32_Ekstak_BS_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0b da c1 e3 04 8d 05 90 01 04 89 00 83 e1 03 61 8b 4d 08 8a 81 90 01 04 84 c0 75 90 01 01 a1 90 01 04 8b 55 0c 03 c1 03 c2 8a 15 90 01 04 30 10 83 3d 90 01 04 03 7e 90 01 01 41 89 4d 08 eb 90 01 01 cf 81 f9 b6 04 00 00 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}