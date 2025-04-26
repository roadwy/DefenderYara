
rule Trojan_Win32_Strab_GFE_MTB{
	meta:
		description = "Trojan:Win32/Strab.GFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 58 f6 ea 8a c8 8b 44 24 50 32 0d ?? ?? ?? ?? 2c 2a f6 2d ?? ?? ?? ?? f6 ac 24 ?? ?? ?? ?? 02 c8 88 4c 24 50 e9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}