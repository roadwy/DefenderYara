
rule Trojan_Win32_Amadey_AP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 5d e8 8b 5d b4 c7 06 00 00 00 00 8b 75 b0 89 31 8b 75 b8 8b 4d bc 89 1f 89 32 89 08 83 ec 04 c7 04 24 20 4e 00 00 ff 15 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}