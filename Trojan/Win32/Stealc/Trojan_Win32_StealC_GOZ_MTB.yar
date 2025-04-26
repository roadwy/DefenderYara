
rule Trojan_Win32_StealC_GOZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.GOZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 a8 81 c2 ?? ?? ?? ?? 2b 55 a0 2b d0 8b 45 d8 31 10 6a 00 e8 ?? ?? ?? ?? 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}