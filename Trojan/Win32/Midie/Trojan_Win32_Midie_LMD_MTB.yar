
rule Trojan_Win32_Midie_LMD_MTB{
	meta:
		description = "Trojan:Win32/Midie.LMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 85 c4 fd ff ff b8 05 40 00 80 89 95 c8 fd ff ff 8d 79 02 66 8b 31 83 c1 02 66 85 f6 75 ?? 2b cf d1 f9 83 f9 40 0f ?? ?? ?? ?? ?? b9 24 00 00 00 8d 85 d0 fd ff ff } //20
		$a_03_1 = {88 10 40 49 75 ?? c7 85 d0 fd ff ff 24 00 00 00 c7 85 e4 fd ff ff 04 00 00 00 33 c0 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}