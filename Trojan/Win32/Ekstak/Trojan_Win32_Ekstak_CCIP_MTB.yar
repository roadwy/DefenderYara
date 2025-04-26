
rule Trojan_Win32_Ekstak_CCIP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CCIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 0c 53 56 57 a0 34 ?? 7c 00 22 05 ?? ?? 7c 00 a2 34 ?? 7c 00 8a 0d 34 ?? 7c 00 80 c9 ?? 88 0d 34 ?? 7c 00 8b 15 2c ?? 7c 00 c1 e2 04 a1 28 ?? 7c 00 23 c2 a3 28 ?? 7c 00 33 c9 8a 0d 35 ?? 7c 00 8b 15 24 ?? 7c 00 83 e2 08 0f af ca a1 2c ?? 7c 00 0b c1 a3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}