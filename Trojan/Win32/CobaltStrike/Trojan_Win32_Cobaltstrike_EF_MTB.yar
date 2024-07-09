
rule Trojan_Win32_Cobaltstrike_EF_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 6a 00 e8 ?? ?? ?? ?? 8b 5d d8 03 5d b0 03 5d e8 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 89 5d b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}