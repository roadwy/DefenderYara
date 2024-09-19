
rule Trojan_Win64_CobaltStrike_OBS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 89 db 29 fb d1 eb 01 fb c1 eb 04 8d 3c db 8d 3c 7f 44 89 db 29 fb 0f b6 1c 1a 42 32 1c 1e 42 88 1c 19 41 ff c3 41 83 fb 0a 48 89 c6 49 0f 44 f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}