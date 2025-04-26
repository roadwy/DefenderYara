
rule Trojan_Win32_Zenpak_ASAO_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d [0-04] a2 [0-04] 30 c8 a2 [0-04] 88 45 ff c7 05 [0-08] a1 [0-04] 05 [0-04] a3 [0-04] 8a 4d ff 0f b6 c1 83 c4 04 5d c3 } //5
		$a_03_1 = {55 89 e5 83 ec 08 8a 45 0c 8a 4d 08 88 0d [0-04] a2 [0-04] 30 c8 a2 [0-04] 8b 15 [0-04] 81 c2 [0-04] 88 45 ff 89 55 f8 8b 45 f8 a3 [0-04] c7 05 [0-08] 8a 4d ff 0f b6 c1 83 c4 08 5d c3 } //5
		$a_03_2 = {55 89 e5 56 8a 45 0c 8a 4d 08 8b 15 [0-04] 88 0d [0-04] 89 d6 81 c6 [0-04] 89 35 [0-04] a2 [0-04] 30 c8 a2 [0-04] 81 c2 [0-04] 89 15 [0-04] 0f b6 c0 5e 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}