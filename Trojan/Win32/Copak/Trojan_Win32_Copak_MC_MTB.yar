
rule Trojan_Win32_Copak_MC_MTB{
	meta:
		description = "Trojan:Win32/Copak.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 3c 24 83 c4 04 81 c3 ?? ?? ?? ?? 01 d9 29 d9 e8 ?? ?? ?? ?? 21 d9 49 81 eb 03 1b 85 47 31 38 81 c1 0f 12 c1 60 40 21 cb 09 cb 39 f0 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}