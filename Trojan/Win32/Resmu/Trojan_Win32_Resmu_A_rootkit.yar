
rule Trojan_Win32_Resmu_A_rootkit{
	meta:
		description = "Trojan:Win32/Resmu.A!rootkit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 68 00 6b 00 74 00 73 00 6b 00 2e 00 74 00 78 00 74 00 } //1 \SystemRoot\System32\chktsk.txt
		$a_01_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 6c 00 6f 00 67 00 66 00 2e 00 6c 00 6f 00 67 00 } //1 \SystemRoot\System32\svlogf.log
		$a_01_2 = {47 45 54 20 2f 73 63 72 69 70 74 2e 70 68 70 3f 74 3d 25 75 26 61 3d } //1 GET /script.php?t=%u&a=
		$a_01_3 = {5c 73 72 65 6e 75 6d 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}