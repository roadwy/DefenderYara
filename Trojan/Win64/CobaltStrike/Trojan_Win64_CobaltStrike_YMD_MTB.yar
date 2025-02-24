
rule Trojan_Win64_CobaltStrike_YMD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 63 db 44 89 df 48 69 ff ?? ?? ?? ?? 48 c1 ef 23 8d 1c bf 8d 1c 9b 01 fb 44 89 df 29 df 0f b6 1c 3a 42 32 1c 1e 42 88 1c 19 41 ff c3 41 83 fb 0b 4c 89 d6 49 0f 44 f1 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}