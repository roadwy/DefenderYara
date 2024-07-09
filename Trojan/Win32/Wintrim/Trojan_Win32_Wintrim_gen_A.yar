
rule Trojan_Win32_Wintrim_gen_A{
	meta:
		description = "Trojan:Win32/Wintrim.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {eb 0a 8b 45 ?? 8b 4d ?? 8d (74|7c) 90 03 01 01 01 08 04 6a 40 68 00 10 00 00 6a 10 6a 00 ff 55 ?? 8b d8 90 03 04 07 83 63 0c 00 c7 43 0c 00 00 00 00 66 81 90 03 01 01 3e 3f 4d 5a 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}