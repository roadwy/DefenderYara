
rule Trojan_Win32_Meterpreter_I_attk{
	meta:
		description = "Trojan:Win32/Meterpreter.I!attk,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 83 ec 18 8b 45 08 89 45 f4 8b 45 f4 ff d0 90 c9 } //1
		$a_01_1 = {00 5f 65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}