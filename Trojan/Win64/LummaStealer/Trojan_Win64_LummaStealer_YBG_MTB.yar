
rule Trojan_Win64_LummaStealer_YBG_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 09 35 ?? ?? ?? ?? 89 44 24 04 8b 44 24 04 09 c8 89 44 24 10 8b 44 24 04 21 c8 f7 d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}