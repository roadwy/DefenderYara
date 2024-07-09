
rule Trojan_Win32_Emotet_PA_MSR{
	meta:
		description = "Trojan:Win32/Emotet.PA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 4f 52 45 4e 41 5c 52 65 6c 65 61 73 65 5c 4d 4f 52 45 4e 41 2e 70 64 62 } //1 \MORENA\Release\MORENA.pdb
		$a_01_1 = {4d 4f 52 45 4e 41 2e 65 78 65 } //1 MORENA.exe
		$a_03_2 = {66 0f b6 32 8b cf 66 d3 e6 42 66 f7 d6 0f b7 ce 88 28 88 48 ?? 03 45 ?? ff 4d ?? 75 } //1
		$a_03_3 = {2a c3 88 07 47 ff 4d [0-04] 8a 02 42 3a c3 7d [0-04] eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}