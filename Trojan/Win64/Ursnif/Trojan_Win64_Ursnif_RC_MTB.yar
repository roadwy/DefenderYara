
rule Trojan_Win64_Ursnif_RC_MTB{
	meta:
		description = "Trojan:Win64/Ursnif.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b9 01 00 00 00 89 41 08 8b 44 24 48 49 8b cf 41 2b c5 03 44 24 4c 46 8d 44 30 12 e8 ?? ?? ?? ?? 8b 45 0c 41 ff c5 2b 45 08 49 81 c7 00 10 00 00 03 45 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}