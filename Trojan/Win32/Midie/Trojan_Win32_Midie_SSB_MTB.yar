
rule Trojan_Win32_Midie_SSB_MTB{
	meta:
		description = "Trojan:Win32/Midie.SSB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 b7 12 00 00 c6 45 fc 02 8b 45 10 50 8b 4d 0c 83 c9 02 51 8b 55 08 52 8b 4d f0 83 c1 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}