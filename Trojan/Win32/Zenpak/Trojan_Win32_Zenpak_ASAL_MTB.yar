
rule Trojan_Win32_Zenpak_ASAL_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 8a 45 ?? 8a 4d ?? 88 0d [0-04] 88 c2 30 ca a2 [0-04] 88 15 [0-04] 8b 35 [0-04] 81 c6 [0-04] 89 35 [0-04] c7 05 [0-08] 0f b6 c2 5e 5d c3 } //5
		$a_03_1 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d [0-04] 88 45 ff 88 4d fe 8a 45 ff a2 [0-04] 8a 4d fe 30 c8 a2 [0-04] c7 05 [0-08] c7 05 [0-08] 0f b6 c0 83 c4 04 5d c3 } //5
		$a_03_2 = {31 f2 88 d4 88 25 [0-04] c7 05 [0-08] c7 05 [0-08] c7 05 [0-08] 0f b6 05 8c 40 1f 10 83 c4 04 5e 5d c3 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}