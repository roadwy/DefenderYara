
rule Trojan_Win32_Khalesi_RL_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f be 02 83 c8 20 0f b6 c8 33 4d ?? 89 4d ?? 8b 55 ?? 83 c2 01 89 55 } //1
		$a_02_1 = {83 c4 04 8b 4d ?? 83 e1 01 8b 15 ?? ?? ?? ?? 0f af 8a ?? ?? ?? ?? 33 c1 89 45 ?? eb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}