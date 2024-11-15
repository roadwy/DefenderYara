
rule Trojan_Win32_Metasploit_PAFV_MTB{
	meta:
		description = "Trojan:Win32/Metasploit.PAFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 20 73 65 65 6d 20 74 6f 20 68 61 76 65 20 61 63 74 69 76 65 20 56 4d 73 20 72 75 6e 6e 69 6e 67 2c 20 70 6c 65 61 73 65 20 73 74 6f 70 20 74 68 65 6d 20 62 65 66 6f 72 65 20 72 75 6e 6e 69 6e 67 20 74 68 69 73 20 74 6f 20 70 72 65 76 65 6e 74 20 63 6f 72 72 75 70 74 69 6f 6e 20 6f 66 20 61 6e 79 20 73 61 76 65 64 20 64 61 74 61 20 6f 66 20 74 68 65 20 56 4d 73 2e } //2 You seem to have active VMs running, please stop them before running this to prevent corruption of any saved data of the VMs.
		$a_01_1 = {56 69 72 74 75 61 6c 42 6f 78 20 70 72 6f 63 65 73 73 20 61 63 74 69 76 65 } //1 VirtualBox process active
		$a_01_2 = {2e 5c 65 78 70 6c 6f 69 74 2e 65 78 65 } //2 .\exploit.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=5
 
}