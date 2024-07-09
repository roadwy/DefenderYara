
rule Trojan_Win32_Mispadu_PA_MTB{
	meta:
		description = "Trojan:Win32/Mispadu.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 45 f0 8b 55 f4 8a 12 80 ea 41 8d 14 92 8d 14 92 8b 4d f4 8a 49 01 80 e9 41 02 d1 8b ce 2a d1 8b cf 2a d1 e8 ?? ?? ?? ?? 8b 55 f0 8b c3 e8 ?? ?? ?? ?? 8d 45 f4 50 8b 45 f4 e8 ?? ?? ?? ?? 8b c8 ba 03 00 00 00 8b 45 f4 e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 85 c0 7f a6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}