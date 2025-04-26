
rule TrojanDropper_Win32_Duetag_A{
	meta:
		description = "TrojanDropper:Win32/Duetag.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 65 74 70 2e 6a 75 6a 75 74 61 6e 67 2e 63 6f 6d } //1 http://getp.jujutang.com
		$a_01_1 = {63 6c 69 73 76 63 2e 65 78 65 } //1 clisvc.exe
		$a_01_2 = {73 68 6f 77 64 6c 6c } //1 showdll
		$a_01_3 = {52 55 4e 44 41 54 41 00 25 73 5c 25 73 00 } //1 啒䑎呁A猥╜s
		$a_01_4 = {5c 4d 46 72 61 6d 65 57 6f 72 6b 73 2e 65 78 65 } //1 \MFrameWorks.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}