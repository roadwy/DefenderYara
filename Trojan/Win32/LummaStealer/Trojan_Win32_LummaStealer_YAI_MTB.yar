
rule Trojan_Win32_LummaStealer_YAI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 04 8d 04 ?? c1 e0 ?? 29 c7 0f b6 44 3c ?? 32 81 40 65 0c 10 8b 54 24 ?? 88 04 0a 83 c1 01 39 4c 24 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}