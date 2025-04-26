
rule Trojan_Win32_Wiessy_B{
	meta:
		description = "Trojan:Win32/Wiessy.B,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {25 73 5f 71 6f 73 65 63 25 64 2e 6d 73 69 } //1 %s_qosec%d.msi
		$a_01_1 = {72 72 72 3a 20 73 70 5f 6d 69 6e 6f 72 20 3d 20 25 64 } //1 rrr: sp_minor = %d
		$a_01_2 = {65 78 65 63 75 74 65 20 66 69 6c 65 20 25 73 20 2e } //1 execute file %s .
		$a_01_3 = {5c 61 74 69 65 6c 66 2e 64 61 74 } //2 \atielf.dat
		$a_01_4 = {6b 72 6e 6c 20 72 69 6b 2e } //2 krnl rik.
		$a_01_5 = {5a 77 56 64 6d 43 6f 6e 74 72 6f 6c } //2 ZwVdmControl
		$a_01_6 = {7e 77 78 70 32 69 6e 73 2e } //2 ~wxp2ins.
		$a_01_7 = {4f 6c 6c 79 44 42 47 2e 45 58 45 } //1 OllyDBG.EXE
		$a_01_8 = {69 64 61 67 2e 65 78 65 } //1 idag.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=10
 
}