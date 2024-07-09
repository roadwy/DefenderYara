
rule Trojan_Win32_Berbew_A_MTB{
	meta:
		description = "Trojan:Win32/Berbew.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 a4 65 00 00 f7 e3 89 85 ?? ?? ?? ?? 89 c3 81 f3 18 2d 00 00 81 f3 a6 21 00 00 89 d8 29 d8 89 c3 6a 01 8d 85 ?? ?? ?? ?? 50 e8 } //1
		$a_00_1 = {81 eb 16 45 00 00 81 eb 64 20 00 00 81 f3 7c 27 00 00 81 eb 92 69 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}