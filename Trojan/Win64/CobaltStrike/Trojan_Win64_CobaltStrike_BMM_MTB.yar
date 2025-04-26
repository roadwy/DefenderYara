
rule Trojan_Win64_CobaltStrike_BMM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 18 41 89 00 41 0f b6 51 fd c1 e2 10 0b d0 41 89 10 41 ?? ?? ?? ?? c1 e1 08 0b ca 49 8b d0 41 89 08 41 ?? ?? ?? ?? 0b c1 41 89 00 49 83 c0 04 41 33 02 4d 8d 52 04 89 02 49 83 ec 01 75 } //1
		$a_03_1 = {5c 78 39 31 5c 78 65 31 5c 78 61 31 39 [0-07] 5c 78 45 39 5c 78 45 38 5c 58 61 31 [0-06] [0-09] 72 30 78 31 30 78 31 30 78 31 [0-11] 4b 4b 42 6f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}