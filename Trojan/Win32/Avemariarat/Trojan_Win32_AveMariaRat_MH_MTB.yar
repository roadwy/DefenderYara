
rule Trojan_Win32_AveMariaRat_MH_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c1 01 89 4d 00 8b 55 fc 83 ea 01 39 55 00 7f ?? 8b 45 fc 83 e8 01 2b 45 00 8b 4d dc 8b 14 81 f7 d2 89 55 e8 83 7d e8 00 74 ?? 8b 45 f8 03 45 00 8a 4d e8 88 08 eb } //1
		$a_00_1 = {8b 55 0c 8a 0c 0a 88 4c 05 08 ba 01 00 00 00 c1 e2 00 b8 01 00 00 00 c1 e0 00 8b 4d 0c 8a 14 11 88 54 05 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}