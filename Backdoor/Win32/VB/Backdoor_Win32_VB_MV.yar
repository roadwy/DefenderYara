
rule Backdoor_Win32_VB_MV{
	meta:
		description = "Backdoor:Win32/VB.MV,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 06 00 00 "
		
	strings :
		$a_00_0 = {74 6d 72 52 65 63 6f 6e 65 63 74 61 72 } //10 tmrReconectar
		$a_00_1 = {74 6d 72 50 69 6e 67 } //10 tmrPing
		$a_00_2 = {74 6d 72 43 61 6d 53 74 61 72 74 } //10 tmrCamStart
		$a_00_3 = {5c 00 63 00 61 00 6d 00 2e 00 6a 00 70 00 67 00 } //1 \cam.jpg
		$a_01_4 = {4d 53 4e 4d 65 73 73 65 6e 67 65 72 } //1 MSNMessenger
		$a_00_5 = {45 00 4e 00 56 00 49 00 41 00 52 00 41 00 52 00 43 00 48 00 49 00 56 00 4f 00 } //1 ENVIARARCHIVO
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=20
 
}