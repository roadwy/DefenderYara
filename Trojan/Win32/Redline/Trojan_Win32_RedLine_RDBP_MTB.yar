
rule Trojan_Win32_RedLine_RDBP_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 99 b9 41 00 00 00 f7 f9 8b 45 08 0f be 0c 10 69 c9 2f d1 ff ff 81 e1 ff 00 00 00 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}