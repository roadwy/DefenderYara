
rule Worm_Win32_Autorun_Y{
	meta:
		description = "Worm:Win32/Autorun.Y,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4b 41 56 33 32 2e 65 78 65 } //1 KAV32.exe
		$a_01_1 = {61 76 70 2e 63 6f 6d } //1 avp.com
		$a_01_2 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //1 taskmgr.exe
		$a_01_3 = {73 76 63 68 30 73 74 2e 65 78 65 } //1 svch0st.exe
		$a_01_4 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d } //1 shell\open\Command=
		$a_01_5 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 63 6f 6d 6d 61 6e 64 3d } //1 shell\explore\command=
		$a_01_6 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \autorun.inf
		$a_01_7 = {46 6c 6f 77 65 72 2e 64 6c 6c } //1 Flower.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}