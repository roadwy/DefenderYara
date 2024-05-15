
rule Trojan_Win64_Mikey_AMY_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 8b 4d df 89 45 d7 4d 85 c9 4c 89 75 ff 48 8d 45 e7 89 75 f7 48 89 44 24 30 4c 8d 45 d7 4d 0f 44 c7 44 89 7c 24 28 45 33 c9 4c 89 7c 24 20 33 d2 48 8d 4d f7 } //00 00 
	condition:
		any of ($a_*)
 
}