
rule Trojan_Win32_Hanictor_VAN_MTB{
	meta:
		description = "Trojan:Win32/Hanictor.VAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 e4 c7 45 ?? f0 83 00 00 c7 45 ?? 00 10 00 00 c7 45 ?? 02 00 00 00 c7 45 ?? 7b 00 00 00 33 c0 89 45 c0 89 65 ?? 81 45 ?? b4 00 00 00 89 6d ?? 83 45 ?? 64 8d 0d ?? ?? ?? ?? 8b 41 f0 89 45 f4 8b 41 ec 89 45 f0 c7 45 ?? 01 10 00 00 c7 45 ?? 1e 01 00 00 c7 45 ?? 83 db 8c 00 } //1
		$a_03_1 = {83 c0 04 89 45 ?? c7 45 ?? 01 10 00 00 c7 45 ?? c4 00 00 00 8b 45 ?? 2d 84 00 00 00 50 8b 45 ?? 48 50 8b 45 ?? 03 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}