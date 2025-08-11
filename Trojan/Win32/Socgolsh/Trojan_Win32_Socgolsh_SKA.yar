
rule Trojan_Win32_Socgolsh_SKA{
	meta:
		description = "Trojan:Win32/Socgolsh.SKA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2d 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 74 00 69 00 6d 00 65 00 6c 00 69 00 6d 00 69 00 74 00 20 00 27 00 30 00 30 00 3a 00 30 00 30 00 3a 00 30 00 30 00 27 00 } //1 -executiontimelimit '00:00:00'
		$a_00_1 = {2d 00 64 00 6f 00 6e 00 74 00 73 00 74 00 6f 00 70 00 69 00 66 00 67 00 6f 00 69 00 6e 00 67 00 6f 00 6e 00 62 00 61 00 74 00 74 00 65 00 72 00 69 00 65 00 73 00 } //1 -dontstopifgoingonbatteries
		$a_00_2 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //1 python
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}