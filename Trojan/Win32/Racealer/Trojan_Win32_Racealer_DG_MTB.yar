
rule Trojan_Win32_Racealer_DG_MTB{
	meta:
		description = "Trojan:Win32/Racealer.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 5d b4 6a 00 e8 ?? ?? ?? ?? 8b 5d b4 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}