
rule Trojan_Win32_Nukesped_MK_MTB{
	meta:
		description = "Trojan:Win32/Nukesped.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 03 c0 48 35 50 5e 00 00 48 89 45 40 48 8b 45 40 48 8b 4d 40 a8 01 ?? ?? 48 8b 45 58 48 33 c8 49 8b c3 48 f7 e1 48 d1 ea 48 8d 04 52 48 3b c8 48 8b 4d 40 } //25
		$a_03_1 = {48 8b 45 50 48 0b c8 48 8b c3 48 f7 e1 48 c1 ea 02 48 8d 04 92 48 2b c8 48 83 f9 01 48 8b 4d 40 48 8b 45 a8 ?? ?? 32 c8 80 e1 0f 80 f9 02 } //10
	condition:
		((#a_03_0  & 1)*25+(#a_03_1  & 1)*10) >=35
 
}