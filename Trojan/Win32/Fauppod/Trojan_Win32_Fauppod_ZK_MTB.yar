
rule Trojan_Win32_Fauppod_ZK_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.ZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d1 81 e1 ff 00 00 00 89 0d 90 01 04 c7 05 90 01 04 e2 02 00 00 8a 0c 0b 8b 55 e8 8b 75 d4 32 0c 32 8b 55 e4 88 0c 32 c7 05 90 01 04 0b 13 00 00 8b 4d f0 39 cf 89 7d cc 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}