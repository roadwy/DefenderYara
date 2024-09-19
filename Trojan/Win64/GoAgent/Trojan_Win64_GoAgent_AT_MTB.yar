
rule Trojan_Win64_GoAgent_AT_MTB{
	meta:
		description = "Trojan:Win64/GoAgent.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 89 c8 48 8d 54 24 70 49 89 dc 48 89 eb 48 c1 f8 3f 48 89 44 24 68 } //1
		$a_81_1 = {54 57 39 36 61 57 78 73 59 53 38 31 4c 6a 41 67 4b } //1 TW96aWxsYS81LjAgK
		$a_00_2 = {48 85 c0 41 0f 9c c0 31 c9 48 89 c7 48 89 de 45 31 c9 31 c0 48 89 cb 0f 1f 00 } //1
		$a_00_3 = {48 c7 c7 08 00 fe 7f 48 8b 07 48 6b c0 64 48 89 44 24 08 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}