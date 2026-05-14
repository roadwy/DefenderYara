
rule Trojan_Win64_Tedy_CL_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 69 64 64 6c 65 72 } //2 Fiddler
		$a_01_1 = {64 6e 53 70 79 } //2 dnSpy
		$a_01_2 = {42 69 6e 61 72 79 4e 69 6e 6a 61 } //2 BinaryNinja
		$a_01_3 = {49 64 61 20 50 72 6f } //2 Ida Pro
		$a_01_4 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //2 ollydbg.exe
		$a_01_5 = {78 36 34 64 62 67 2e 65 78 65 } //2 x64dbg.exe
		$a_01_6 = {56 6d 74 6f 6f 6c 73 64 2e 65 78 65 } //2 Vmtoolsd.exe
		$a_01_7 = {76 62 6f 78 74 72 61 79 2e 65 78 65 } //2 vboxtray.exe
		$a_01_8 = {44 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 21 } //2 Debugger detected!
		$a_01_9 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //2 joeboxcontrol.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=20
 
}