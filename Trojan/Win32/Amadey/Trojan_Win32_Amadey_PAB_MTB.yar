
rule Trojan_Win32_Amadey_PAB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 04 8b 00 eb 03 8b 45 cc 0f be 04 10 8b 04 81 83 f8 ff 74 5c c1 e7 06 03 f8 83 c3 06 78 46 8b cb 8b d7 d3 fa 8b 4e ?? 88 55 e0 3b 4e 14 73 1a 83 7e 14 10 8d 41 01 89 46 10 8b c6 72 02 8b 06 88 14 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}