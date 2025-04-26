
rule Trojan_Win32_Stealc_GKA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.GKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 4c 05 ?? c1 f9 02 03 d1 8b 45 e8 03 45 f8 88 10 8b 4d f8 83 c1 01 89 4d f8 ba ?? ?? ?? ?? 6b c2 ?? 0f be 4c ?? f4 83 f9 ?? 0f 84 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}