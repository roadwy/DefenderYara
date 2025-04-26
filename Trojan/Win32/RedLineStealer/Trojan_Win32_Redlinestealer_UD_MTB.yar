
rule Trojan_Win32_Redlinestealer_UD_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.UD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 33 d2 b9 ?? ?? ?? ?? f7 f1 a1 ?? ?? ?? ?? 0f be 0c 10 8b 55 ?? 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d ?? 88 81 ?? ?? ?? ?? eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}