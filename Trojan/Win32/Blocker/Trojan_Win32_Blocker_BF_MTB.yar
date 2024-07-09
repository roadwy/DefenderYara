
rule Trojan_Win32_Blocker_BF_MTB{
	meta:
		description = "Trojan:Win32/Blocker.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 2b c2 66 03 c8 8b 84 2f 97 fc ff ff 05 04 5c 01 01 89 84 2f 97 fc ff ff 8b f2 2b f3 8b eb c1 e5 04 83 ee 03 03 eb 89 35 [0-04] 2b f5 8b 6c 24 14 83 c5 04 81 fd 59 04 00 00 66 89 0d [0-04] a3 [0-04] 89 6c 24 14 0f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}