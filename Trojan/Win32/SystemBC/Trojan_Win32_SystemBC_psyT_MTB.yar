
rule Trojan_Win32_SystemBC_psyT_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 9c dd 53 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 33 c0 89 08 50 45 43 6f 6d 70 61 63 74 32 00 13 5f ac 93 f6 da 0e 49 b8 ?? ?? ?? ?? 02 e4 d4 e7 a3 09 ec c0 98 a1 5c b1 a8 f6 e3 c3 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}