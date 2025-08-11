
rule Trojan_Win64_LummaStealer_PGG_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c1 0f b6 c1 [0-0a] 48 63 [0-0a] 30 04 [0-02] 8b [0-0a] 83 ?? 01 [0-0a] b8 [0-0c] 3d [0-08] 0f 8f ?? ?? ff ff e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}