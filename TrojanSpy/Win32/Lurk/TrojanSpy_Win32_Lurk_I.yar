
rule TrojanSpy_Win32_Lurk_I{
	meta:
		description = "TrojanSpy:Win32/Lurk.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff 90 64 02 00 00 8b 45 f4 83 c0 40 50 8b 45 f4 ff 90 68 02 00 00 } //1
		$a_01_1 = {b8 aa aa aa aa 76 39 56 0f be 0a 83 c9 20 f6 c3 01 8b f0 75 0e c1 e6 07 33 ce 8b f0 c1 ee 03 } //1
		$a_03_2 = {81 ff ce 01 06 5c 0f 84 90 01 04 be 2d 4f c3 66 3b fe 90 00 } //1
		$a_01_3 = {26 61 71 3d 66 26 61 71 69 3d 26 61 71 6c 3d 26 6f 71 3d } //1 &aq=f&aqi=&aql=&oq=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}