
rule Trojan_Win32_Ekstak_CCJR_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCJR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a c1 32 c2 8b d6 24 ?? a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? d1 ea 03 c2 33 d2 a3 ?? ?? ?? ?? 83 e0 07 8a d1 0f af c2 03 f0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}