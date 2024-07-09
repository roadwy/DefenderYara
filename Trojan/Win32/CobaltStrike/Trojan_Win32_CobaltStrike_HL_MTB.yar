
rule Trojan_Win32_CobaltStrike_HL_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {a5 53 32 1c 7b a1 ?? ?? ?? ?? 18 a3 ?? ?? ?? ?? ?? 69 ?? ae 35 } //1
		$a_03_1 = {a4 00 a4 00 ?? ?? ?? ?? 41 00 2b 00 0c ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}