
rule Trojan_Win32_SmokeLoader_NEAC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 33 45 08 83 25 90 01 05 2b d8 89 45 0c 8b c3 c1 e0 04 89 5d e8 89 45 08 8b 45 e4 01 45 08 8b 45 e8 03 45 fc 89 45 f8 ff 75 f8 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}