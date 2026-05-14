
rule Trojan_Win32_Fragtor_LR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 53 58 ff 43 14 8b 4b 14 8b 42 50 0f af c1 3d d0 07 00 00 73 ?? 8d 41 01 89 43 14 8b 4a 50 0f af c8 } //20
		$a_03_1 = {bb 0a 00 00 00 3b cb 0f 4c cb 89 4a 50 8b 4d f8 5b 85 c9 78 ?? 89 8a b8 00 00 00 85 c0 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}