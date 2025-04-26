
rule Trojan_Win32_Meterpreter_J_attk{
	meta:
		description = "Trojan:Win32/Meterpreter.J!attk,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 83 ec 28 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 45 f4 c7 45 f0 00 00 00 00 8b 45 f4 8d 55 f0 89 54 24 0c c7 44 24 08 40 00 00 00 89 44 24 04 8b 45 08 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 10 8b 45 08 ff d0 90 90 c9 c3 } //1
		$a_01_1 = {00 5f 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 36 34 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}