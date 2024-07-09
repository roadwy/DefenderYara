
rule Trojan_Win32_Ekstak_S_MSR{
	meta:
		description = "Trojan:Win32/Ekstak.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 56 2c 8a 0c 18 52 88 0d ?? ?? ?? 00 ff 57 08 8a 0d ?? ?? ?? 00 8a 54 24 18 02 c1 8b 0d ?? ?? ?? 00 32 c2 a2 ?? ?? ?? 00 88 04 19 8b 44 24 14 83 f8 10 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}