
rule Trojan_Win32_Brolocker_A{
	meta:
		description = "Trojan:Win32/Brolocker.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 6e 64 53 74 31 5c 44 65 66 61 75 6c 74 00 } //1
		$a_00_1 = {45 52 52 4f 52 20 68 61 73 20 6f 63 63 75 72 65 64 21 20 53 65 6e 64 69 6e 67 20 45 72 72 6f 72 20 52 65 70 6f 72 74 20 2e 2e 2e 00 } //1
		$a_03_2 = {8b f0 68 80 ee 36 00 ff 15 ?? ?? 40 00 4e 75 f2 83 3d ?? ?? 40 00 00 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}