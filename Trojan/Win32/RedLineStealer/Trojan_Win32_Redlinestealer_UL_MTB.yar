
rule Trojan_Win32_Redlinestealer_UL_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 45 ?? ba ?? ?? ?? ?? f7 75 ?? 8b 45 ?? 01 d0 0f b6 00 83 f0 ?? 89 c3 8b 55 ?? 8b 45 ?? 01 d0 31 d9 89 ca 88 10 83 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}