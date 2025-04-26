
rule Trojan_Win32_Nymaim_SD_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.SD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c0 2b 06 f7 d8 83 ee fc 83 e8 2e c1 c8 08 29 f8 83 e8 01 50 5f c1 c7 0a c1 cf 02 c7 03 00 00 00 00 31 03 83 c3 04 83 e9 04 85 c9 75 d2 5b 8b 15 04 f7 49 00 52 89 1d 14 f7 49 00 ff 15 14 f7 49 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}