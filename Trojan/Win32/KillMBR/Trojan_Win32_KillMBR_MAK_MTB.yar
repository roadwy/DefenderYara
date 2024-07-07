
rule Trojan_Win32_KillMBR_MAK_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  1
		$a_80_1 = {4e 4f 20 45 53 43 41 50 45 } //NO ESCAPE  1
		$a_80_2 = {64 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 6b 69 6c 6c 20 74 68 65 20 70 72 6f 63 65 73 73 } //do not try to kill the process  1
		$a_80_3 = {50 61 79 6c 6f 61 64 } //Payload  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule Trojan_Win32_KillMBR_MAK_MTB_2{
	meta:
		description = "Trojan:Win32/KillMBR.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {6c 6f 74 20 6f 66 20 64 65 73 74 72 75 63 74 69 76 65 20 70 6f 74 65 6e 74 69 61 6c } //lot of destructive potential  1
		$a_80_1 = {59 6f 75 20 77 69 6c 6c 20 6c 6f 73 65 20 61 6c 6c 20 6f 66 20 79 6f 75 72 20 64 61 74 61 20 69 66 20 79 6f 75 20 63 6f 6e 74 69 6e 75 65 } //You will lose any of your data if you continue  1
		$a_80_2 = {74 72 6f 6a 61 6e } //trojan  1
		$a_80_3 = {66 69 6e 61 6c 20 63 68 61 6e 63 65 20 74 6f 20 73 74 6f 70 20 74 68 69 73 20 70 72 6f 67 72 61 6d } //final chance to stop this program  1
		$a_80_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  1
		$a_80_5 = {66 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 68 61 6e 64 6c 65 20 74 6f 20 70 68 79 73 69 63 61 6c 20 64 72 69 76 65 } //failed to open handle to physical drive  1
		$a_80_6 = {66 61 69 6c 65 64 20 74 6f 20 6f 76 65 72 77 72 69 74 65 20 62 6f 6f 74 20 64 61 74 61 } //failed to overwrite boot data  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}