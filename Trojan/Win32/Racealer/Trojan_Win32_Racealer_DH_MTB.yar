
rule Trojan_Win32_Racealer_DH_MTB{
	meta:
		description = "Trojan:Win32/Racealer.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 ?? ?? ?? ?? 8b 55 b4 2b d0 8b 45 ec 31 10 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}