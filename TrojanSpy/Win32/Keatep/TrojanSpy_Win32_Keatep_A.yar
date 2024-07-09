
rule TrojanSpy_Win32_Keatep_A{
	meta:
		description = "TrojanSpy:Win32/Keatep.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 25 83 bd ?? ?? ff ff 15 74 1c 81 bd ?? ?? ff ff 49 08 00 00 74 10 81 bd ?? ?? ff ff 49 08 00 00 0f 85 ?? ?? 00 00 8b ?? ?? 0f be ?? 83 ?? 55 74 0b 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}