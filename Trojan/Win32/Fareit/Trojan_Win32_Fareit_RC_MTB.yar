
rule Trojan_Win32_Fareit_RC_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 51 0c 8b 8d 78 ff ff ff 8b b5 70 ff ff ff 8a 04 08 32 04 32 8b 4d cc 8b 51 0c 8b 8d 68 ff ff ff 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 88 45 fb 8b 55 fc 8a 45 fb 88 02 b0 31 30 02 83 45 fc 01 73 05 e8 cb a2 f9 ff ff 45 f4 41 81 7d f4 a9 59 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}