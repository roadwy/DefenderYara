
rule Trojan_Win64_KillAV_MKX_MTB{
	meta:
		description = "Trojan:Win64/KillAV.MKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4d 0f 44 dc 4c 89 f0 31 d2 49 f7 f2 49 89 d0 48 89 d9 48 d1 e9 49 0f af ca 48 89 d8 31 d2 48 f7 f1 48 d1 e8 48 0f af d8 48 89 da c4 c2 fb f6 c5 43 8a 0c 31 43 32 0c 03 48 c1 e8 90 01 01 30 c1 43 88 0c 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}