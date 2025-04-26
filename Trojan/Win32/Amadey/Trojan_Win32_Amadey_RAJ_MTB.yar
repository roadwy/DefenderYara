
rule Trojan_Win32_Amadey_RAJ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 45 ec 8b 45 ec 83 45 f4 ?? 29 45 f4 83 6d f4 ?? 8b 45 f4 8d 4d fc e8 ?? ?? ?? ?? 8b 45 d8 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 03 c3 33 c2 31 45 fc 2b 75 fc 8b 45 d4 29 45 f8 ff 4d e8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}