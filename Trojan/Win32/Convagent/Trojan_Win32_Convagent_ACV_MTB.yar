
rule Trojan_Win32_Convagent_ACV_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ACV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 9c ab 41 00 53 e8 ?? ?? ?? ?? a3 24 37 44 00 68 b0 ab 41 00 53 e8 ?? ?? ?? ?? a3 28 37 44 00 68 c4 ab 41 00 53 e8 ?? ?? ?? ?? a3 1c 37 44 00 68 dc ab 41 00 53 e8 ?? ?? ?? ?? a3 20 37 44 00 68 f4 ab 41 00 53 } //1
		$a_03_1 = {68 98 99 42 00 a1 f0 26 44 00 50 e8 ?? ?? ?? ?? a3 88 37 44 00 68 a8 99 42 00 a1 f0 26 44 00 50 e8 ?? ?? ?? ?? a3 8c 37 44 00 68 bc 99 42 00 a1 f0 26 44 00 50 e8 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}