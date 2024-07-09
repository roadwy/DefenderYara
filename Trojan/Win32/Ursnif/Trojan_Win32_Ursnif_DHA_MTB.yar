
rule Trojan_Win32_Ursnif_DHA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 d7 01 15 ?? ?? ?? ?? 8b d0 2b d7 bd 97 2b 00 00 03 d5 0f b7 fa 81 c1 00 27 80 01 89 0e 8b 35 ?? ?? ?? ?? 0f b7 d7 2b f7 03 f5 83 c3 ?? 83 c2 ?? 81 fb ?? ?? ?? ?? 0f b7 f6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}