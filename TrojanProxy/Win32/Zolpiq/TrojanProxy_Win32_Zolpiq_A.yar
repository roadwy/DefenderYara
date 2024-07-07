
rule TrojanProxy_Win32_Zolpiq_A{
	meta:
		description = "TrojanProxy:Win32/Zolpiq.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 73 69 6d 61 67 65 2e 64 61 74 } //1 msimage.dat
		$a_01_1 = {68 3f 00 0f 00 56 56 ff d0 3b c6 75 04 33 c0 5e c3 68 ff 01 0f 00 ff 74 24 0c 50 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanProxy_Win32_Zolpiq_A_2{
	meta:
		description = "TrojanProxy:Win32/Zolpiq.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {51 57 54 20 2f 57 45 52 72 63 68 41 6e 3d } //1 QWT /WERrchAn=
		$a_01_1 = {53 68 61 72 6b 43 6f 6e 6e 65 63 74 2e 2e 2e 25 73 3a 25 64 } //1 SharkConnect...%s:%d
		$a_01_2 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 53 75 62 6d 69 74 22 } //1 Content-Disposition: form-data; name="Submit"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}