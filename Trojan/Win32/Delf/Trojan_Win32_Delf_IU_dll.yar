
rule Trojan_Win32_Delf_IU_dll{
	meta:
		description = "Trojan:Win32/Delf.IU!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {21 40 23 77 61 6e 67 6a 69 26 68 79 7a 2a 2a } //01 00  !@#wangji&hyz**
		$a_01_1 = {79 64 67 69 64 63 6e 61 66 67 2e 64 61 74 } //01 00  ydgidcnafg.dat
		$a_01_2 = {75 64 70 5c 68 6a 6f 62 31 32 33 5c 63 6f 6d } //01 00  udp\hjob123\com
		$a_02_3 = {2e 6c 6c 61 64 73 2e 63 6e 90 02 05 2f 69 65 62 61 72 2f 74 74 65 73 74 2e 61 73 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}