
rule Trojan_Win32_Bluesix_A{
	meta:
		description = "Trojan:Win32/Bluesix.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 01 6a 02 a3 ?? ?? 40 00 66 c7 05 ?? ?? 40 00 02 00 e8 ?? ?? 00 00 6a 10 68 ?? ?? 40 00 50 a3 ?? ?? 40 00 e8 ?? 03 00 00 83 f8 ff 75 18 8b 15 ?? ?? 40 00 6a 10 68 ?? ?? 40 00 52 e8 ?? ?? 00 00 83 f8 ff 74 e8 a1 ?? ?? 40 00 6a 00 68 00 20 00 00 68 ?? ?? 40 00 50 e8 ?? 02 00 00 85 c0 } //1
		$a_01_1 = {43 6c 69 65 6e 74 52 61 6e 64 6f 6d 5b 33 32 5d } //1 ClientRandom[32]
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}