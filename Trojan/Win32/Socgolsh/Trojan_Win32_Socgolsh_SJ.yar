
rule Trojan_Win32_Socgolsh_SJ{
	meta:
		description = "Trojan:Win32/Socgolsh.SJ,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 } //1 schtasks
		$a_00_1 = {73 00 73 00 68 00 2e 00 65 00 78 00 65 00 } //1 ssh.exe
		$a_00_2 = {53 00 74 00 72 00 69 00 63 00 74 00 48 00 6f 00 73 00 74 00 4b 00 65 00 79 00 43 00 68 00 65 00 63 00 6b 00 69 00 6e 00 67 00 3d 00 6e 00 6f 00 } //1 StrictHostKeyChecking=no
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}