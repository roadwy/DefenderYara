
rule Trojan_Win32_Feplec_A{
	meta:
		description = "Trojan:Win32/Feplec.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b1 ff 2a 08 88 08 40 4a 75 f6 c3 } //1
		$a_01_1 = {be 00 00 00 10 81 c6 00 00 01 00 6a 40 68 00 30 00 00 8b 47 50 50 8b 47 34 03 c6 50 } //1
		$a_03_2 = {8b 00 ff d0 8b f0 60 3b 1d ?? ?? ?? ?? 0f 85 94 00 00 00 83 fe 32 0f 8e 8b 00 00 00 8d 45 f8 8b d7 e8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=2
 
}