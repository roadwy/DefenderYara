
rule Trojan_Win64_SantaStealer_YBF_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.YBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5a 3e 1f 8d c7 85 ?? ?? ?? ?? 8e 6d 4c 2b 8b 45 ?? 8b 4d ?? 0f ac c1 1d 89 4d ?? 8b 85 ?? ?? 00 00 0f a4 85 ?? ?? 00 00 1b 8b 45 ?? 33 85 ?? 03 00 00 89 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}