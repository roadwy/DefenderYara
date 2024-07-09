
rule Trojan_Win32_Ursnif_GA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 8a 54 24 0c 32 d0 41 88 16 46 ff 4c 24 08 75 ee } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Ursnif_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 74 30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d [0-10] 83 7d [0-10] 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ursnif_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 f0 2b de 8b 37 03 eb b3 59 f6 eb 8a da 2a d8 81 3d [0-08] 88 1d [0-04] 90 18 8b 1d [0-04] 81 c6 [0-04] 8a ca 2a cb 89 37 80 c1 ?? 83 c7 ?? 83 6c 24 ?? 01 89 35 [0-04] 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}