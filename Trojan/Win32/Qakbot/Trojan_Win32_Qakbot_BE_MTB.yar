
rule Trojan_Win32_Qakbot_BE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c1 8b 4d 64 89 41 1c 8b 55 64 8b 42 48 35 c4 4e 0e 00 8b 4d 64 03 81 d0 00 00 00 8b 55 64 89 82 d0 00 00 00 e9 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}