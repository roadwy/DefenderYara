
rule Trojan_Win32_VidarStealer_UA_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.UA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 0f 43 4d ?? 33 d2 f7 75 ?? 8b 45 ?? 8a 0c 0a 32 0c 38 88 4d ?? 3b 5e ?? ?? ?? 88 0b ff 46 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}