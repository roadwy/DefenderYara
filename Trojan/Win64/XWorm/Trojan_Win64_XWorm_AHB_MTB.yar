
rule Trojan_Win64_XWorm_AHB_MTB{
	meta:
		description = "Trojan:Win64/XWorm.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8d 0c 52 4d 01 c1 49 ff c0 4d 89 ca 49 d1 ea 4c 89 ca 48 31 c2 41 f6 c1 ?? 49 0f 44 d2 48 89 55 20 49 81 f8 ?? ?? ?? ?? 75 } //30
		$a_01_1 = {50 52 4f 54 45 43 54 5f 56 32 5f 50 41 59 4c 4f 41 44 } //20 PROTECT_V2_PAYLOAD
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}