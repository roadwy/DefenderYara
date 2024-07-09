
rule Trojan_Win32_ChePro_AB_MTB{
	meta:
		description = "Trojan:Win32/ChePro.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 98 8b 45 ec 8b 55 d4 01 02 8b 45 c4 03 45 ?? 03 45 ec 03 45 98 89 45 a4 6a 00 e8 ?? ?? ?? ?? 8b 5d a4 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 9f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}