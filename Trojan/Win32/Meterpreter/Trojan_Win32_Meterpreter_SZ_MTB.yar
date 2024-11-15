
rule Trojan_Win32_Meterpreter_SZ_MTB{
	meta:
		description = "Trojan:Win32/Meterpreter.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 69 6e 67 20 63 6f 6d 6d 61 6e 64 5f 65 78 65 63 } //2 Calling command_exec
		$a_01_1 = {43 61 6c 6c 69 6e 67 20 64 65 63 6f 64 65 5f 70 61 79 6c 6f 61 64 } //2 Calling decode_payload
		$a_01_2 = {65 78 65 63 5f 73 68 65 6c 6c 63 6f 64 65 36 34 20 63 61 6c 6c 65 64 } //2 exec_shellcode64 called
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}