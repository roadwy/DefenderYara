
rule Trojan_Win32_Ekstak_GLX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b ec 6a ff 68 ?? 83 64 00 68 ?? 7d 64 00 64 a1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 } //10
		$a_03_1 = {8b ec 6a ff 68 ?? 97 64 00 68 ?? 85 64 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 } //10
		$a_80_2 = {4d 6f 6f 6e 20 43 6f 64 65 63 } //Moon Codec  1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*1) >=11
 
}