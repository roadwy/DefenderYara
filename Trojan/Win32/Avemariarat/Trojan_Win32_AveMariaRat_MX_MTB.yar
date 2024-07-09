
rule Trojan_Win32_AveMariaRat_MX_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 40 d1 e0 33 c9 41 d1 e1 8b 55 ?? 8a 04 02 88 44 0d ?? 33 c0 40 6b c0 ?? 33 c9 41 6b c9 ?? 8b 55 ?? 8a 04 02 88 44 0d ?? 33 c0 40 6b c0 ?? 8b 4d ?? c6 04 01 ?? 33 c0 40 c1 e0 ?? 8b 4d ?? c6 04 01 ?? 33 c0 40 d1 e0 8b 4d 0c c6 04 01 00 33 c0 40 6b c0 ?? 8b 4d ?? c6 04 01 ?? 83 65 [0-05] eb } //5
		$a_01_1 = {4e 74 44 65 6c 61 79 45 78 65 63 75 74 69 6f 6e } //1 NtDelayExecution
		$a_01_2 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}