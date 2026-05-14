
rule Trojan_Win32_Poma_SD_MTB{
	meta:
		description = "Trojan:Win32/Poma.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 02 30 01 8d 04 0b 3b c7 7d ?? 8a 42 ?? 83 c2 ?? 30 41 ?? 83 c1 ?? 8b 45 ?? 03 c2 83 f8 ?? 7c ?? 8b 45 ?? 8b 5d ?? 83 c0 ?? ff 45 ?? 83 45 ?? ?? 3b c7 8b 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}