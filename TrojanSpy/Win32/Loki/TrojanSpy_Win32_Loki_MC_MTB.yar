
rule TrojanSpy_Win32_Loki_MC_MTB{
	meta:
		description = "TrojanSpy:Win32/Loki.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 e8 28 ff ff ff b8 ?? ?? ?? ?? 31 c9 68 ?? ?? ?? ?? 5a 80 34 01 ?? 41 39 d1 75 ?? 05 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}