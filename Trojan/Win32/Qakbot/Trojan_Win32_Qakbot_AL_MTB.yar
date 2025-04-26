
rule Trojan_Win32_Qakbot_AL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 47 4c 37 30 00 } //1 䜀㝌0
		$a_01_1 = {ac 02 c3 32 c3 c0 c8 08 aa 49 e9 } //1
		$a_03_2 = {8b 55 f0 68 50 3c 0a 60 68 5a 6e 00 00 6a 00 e8 ?? ?? ?? ?? 5a ff d0 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Qakbot_AL_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 2d 80 0d 00 00 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 [0-20] e8 90 0a 40 00 8b 45 ?? 8b 55 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}