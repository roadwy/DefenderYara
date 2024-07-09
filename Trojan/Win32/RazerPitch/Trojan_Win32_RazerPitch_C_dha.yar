
rule Trojan_Win32_RazerPitch_C_dha{
	meta:
		description = "Trojan:Win32/RazerPitch.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 43 5e 41 32 4b 40 41 32 ?? 41 88 4b 40 42 0f b6 04 ?? 41 30 43 41 41 0f b6 43 5f 42 0f b6 04 ?? 41 30 43 42 41 0f b6 43 5c 42 0f b6 04 ?? 41 30 43 43 41 0f b6 ?? 02 c0 45 84 ?? 44 0f b6 ?? 79 04 } //1
		$a_01_1 = {0f 1f 40 00 66 39 18 74 14 48 83 c0 02 49 ff c9 75 f2 41 ba 57 00 07 80 48 8b cb eb 16 4d 85 c9 75 0b 41 ba 57 00 07 80 48 8b cb eb 06 49 8b c8 49 2b c9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}