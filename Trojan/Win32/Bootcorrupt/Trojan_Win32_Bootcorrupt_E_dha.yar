
rule Trojan_Win32_Bootcorrupt_E_dha{
	meta:
		description = "Trojan:Win32/Bootcorrupt.E!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 42 52 20 4b 69 6c 6c 65 72 } //1 MBR Killer
		$a_01_1 = {61 64 76 61 70 69 33 32 3a 3a 4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 28 69 2c 20 69 2c 20 2a 69 29 20 69 20 28 2d 31 2c 20 30 78 30 30 30 38 7c 30 78 30 30 32 30 2c 20 2e 72 31 29 20 69 20 2e 72 30 } //1 advapi32::OpenProcessToken(i, i, *i) i (-1, 0x0008|0x0020, .r1) i .r0
		$a_01_2 = {6b 65 72 6e 65 6c 33 32 3a 3a 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 28 70 2c 20 69 2c 20 69 2c 20 2a 69 29 20 69 20 28 72 31 2c 20 36 2c 20 30 78 34 30 2c 20 2e 72 32 29 20 2e 72 30 } //1 kernel32::VirtualProtect(p, i, i, *i) i (r1, 6, 0x40, .r2) .r0
		$a_01_3 = {5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 25 64 } //1 \\.\PHYSICALDRIVE%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}