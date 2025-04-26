
rule Trojan_Win32_Lokibot_SZ_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f0 54 6a 40 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 90 05 10 01 90 33 c0 a3 ?? ?? ?? ?? 90 05 10 01 90 33 db 90 05 10 01 90 b2 ?? 8b c3 8b fe 03 f8 a1 ?? ?? ?? ?? 8a 80 ?? ?? ?? ?? 90 05 10 01 90 32 c2 88 07 } //1
		$a_03_1 = {b9 01 00 00 00 8b da 03 d9 c6 03 ?? 41 48 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}