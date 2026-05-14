
rule Trojan_Win64_Tedy_AHM_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 d2 41 0f b6 c0 2a c2 04 ?? 43 32 84 29 ?? ?? ?? ?? ?? 88 04 09 41 ff c0 4d 8d 49 ?? 41 83 f8 ?? 72 } //30
		$a_01_1 = {48 0f 47 45 c0 c6 40 08 65 48 8d 45 c0 48 83 7d d8 0f 48 0f 47 45 c0 c6 40 09 65 48 8d 45 c0 48 83 7d d8 0f } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}