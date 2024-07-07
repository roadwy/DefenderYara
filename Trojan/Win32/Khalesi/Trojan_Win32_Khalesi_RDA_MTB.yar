
rule Trojan_Win32_Khalesi_RDA_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 45 69 44 20 76 30 2e 39 35 } //1 PEiD v0.95
		$a_01_1 = {43 68 65 61 74 20 45 6e 67 69 6e 65 20 36 2e 37 } //1 Cheat Engine 6.7
		$a_01_2 = {57 69 6e 44 62 67 46 72 61 6d 65 43 6c 61 73 73 } //1 WinDbgFrameClass
		$a_01_3 = {49 6d 6d 75 6e 69 74 79 44 65 62 75 67 67 65 72 2e 65 78 65 } //1 ImmunityDebugger.exe
		$a_01_4 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //1 joeboxcontrol.exe
		$a_01_5 = {6a 6f 65 62 6f 78 73 65 72 76 65 72 2e 65 78 65 } //1 joeboxserver.exe
		$a_01_6 = {6f 70 65 6e 20 25 73 20 74 79 70 65 20 63 64 61 75 64 69 6f 20 61 6c 69 61 73 20 63 64 20 77 61 69 74 20 73 68 61 72 65 61 62 6c 65 } //1 open %s type cdaudio alias cd wait shareable
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}