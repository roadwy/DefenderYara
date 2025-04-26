
rule Trojan_Win64_Lazy_AMCP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 33 c9 ff 15 [0-1e] 33 d2 33 c9 ff 15 [0-1e] 45 33 c0 48 8d 15 ?? ?? ?? ?? 33 c9 ff 15 [0-1e] 33 d2 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}