
rule Trojan_Win32_DarkGate_DA_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.DA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {2f 00 63 00 20 00 77 00 6d 00 69 00 63 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 67 00 65 00 74 00 20 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 } //10 /c wmic ComputerSystem get domain
		$a_00_2 = {3e 00 20 00 43 00 3a 00 5c 00 } //1 > C:\
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=12
 
}