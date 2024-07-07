
rule Trojan_Win32_Farfli_CT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c f7 d8 89 45 0c b8 34 00 00 00 99 f7 7d 0c 83 c0 06 89 45 fc 8b 4d fc 69 c9 b9 79 37 9e 89 4d f4 8b 55 08 33 c0 8a 02 89 45 ec 8b 4d f4 c1 e9 02 83 e1 03 89 4d f0 8b 55 0c 83 ea 01 89 55 f8 eb 09 8b 45 f8 83 e8 01 89 45 f8 83 7d f8 00 76 69 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}