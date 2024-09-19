
rule Trojan_Win32_Fauppod_GYA_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 20 4a b8 ?? ?? ?? ?? 48 eb ?? 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 8d 05 ?? ?? ?? ?? 31 28 89 d0 89 d8 50 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}