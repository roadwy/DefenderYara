
rule Trojan_Win32_StealC_GMH_MTB{
	meta:
		description = "Trojan:Win32/StealC.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 04 0e 81 fa 8d 00 00 00 75 ?? c7 05 ?? ?? ?? ?? bc 17 00 00 41 3b ca 72 } //5
		$a_03_1 = {33 c0 33 d2 8d 4c 24 ?? 51 66 89 54 24 ?? 66 89 44 24 ?? 8b 54 24 ?? 52 50 50 50 ff d6 83 eb 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}