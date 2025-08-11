
rule Trojan_Win32_Donut_YAB_MTB{
	meta:
		description = "Trojan:Win32/Donut.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 e7 } //5
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e } //1 schtasks /create /tn
		$a_01_2 = {64 6a 6b 67 67 6f 73 6a 2e 62 61 74 } //1 djkggosj.bat
		$a_03_3 = {0f b6 cb 32 b9 ?? ?? ?? ?? 8a 6d ff 8a 48 f3 8d 70 04 8a 58 f4 32 cf 32 5d fe 42 88 48 03 8a 48 f5 32 4d fd 88 48 05 8a 48 f6 32 cd } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*5) >=12
 
}