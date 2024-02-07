
rule Trojan_Win32_Younmac{
	meta:
		description = "Trojan:Win32/Younmac,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 06 6a 01 6a 02 e8 90 01 04 8b d8 83 fb ff 90 02 03 47 83 ff 0a 0f 8f 90 01 02 00 00 68 00 a0 00 00 e8 90 01 04 eb 90 00 } //01 00 
		$a_01_1 = {22 43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 } //01 00  "C:\Windows\iexplore.exe"
		$a_01_2 = {63 3a 5c 61 75 74 6f 65 78 65 63 2e 64 61 74 } //01 00  c:\autoexec.dat
		$a_01_3 = {53 4c 4f 57 4e 45 54 00 } //01 00  䱓坏䕎T
		$a_01_4 = {75 6e 70 61 73 73 72 75 6e 2e 63 66 6d 20 48 54 54 50 2f 31 00 } //01 00 
		$a_01_5 = {57 69 6e 33 32 4c 64 72 2e 44 6c 6c } //01 00  Win32Ldr.Dll
		$a_01_6 = {4d 61 63 5f 53 6e 69 66 66 5f 46 69 6c 65 4d 61 70 00 } //01 00  慍彣湓晩彦楆敬慍p
		$a_01_7 = {59 4f 4e 47 5f 4d 61 63 5f 53 6e 69 66 66 5f } //00 00  YONG_Mac_Sniff_
	condition:
		any of ($a_*)
 
}