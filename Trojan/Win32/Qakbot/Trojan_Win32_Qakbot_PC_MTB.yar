
rule Trojan_Win32_Qakbot_PC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 65 33 34 35 34 2e 64 6c 6c } //1 ole3454.dll
		$a_01_1 = {5c 44 6c 6c 5c 6f 75 74 2e 70 64 62 } //1 \Dll\out.pdb
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_03_3 = {d3 fa 89 15 ?? ?? ?? ?? 8b 4d ?? 2b 4d ?? 2b 0d ?? ?? ?? ?? 03 4d ?? 8b 45 ?? d3 f8 33 45 ?? 8b 55 ?? 8b 0d ?? ?? ?? ?? d3 fa 33 55 ?? 8b 4d ?? 2b 4d ?? 8b 35 ?? ?? ?? ?? d3 e6 33 d6 3b c2 7f } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*4) >=7
 
}