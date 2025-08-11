
rule Trojan_Win64_CobaltStrike_LIT_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b d6 48 2b d7 88 04 17 ff c1 8b c1 48 ff c7 25 03 00 00 80 7d ?? ff c8 83 c8 fc ff c0 48 98 8a 04 18 32 07 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_LIT_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.LIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 41 f7 f9 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 0c 10 ?? 8b 44 24 48 42 32 0c 00 42 88 0c 06 49 ff c0 eb } //1
		$a_01_1 = {43 68 65 63 6b 4d 65 6e 75 52 61 64 69 6f } //1 CheckMenuRadio
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}