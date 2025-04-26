
rule TrojanSpy_BAT_Rulervth_A_bit{
	meta:
		description = "TrojanSpy:BAT/Rulervth.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 00 48 00 33 00 52 00 55 00 4c 00 45 00 52 00 5f 00 4b 00 45 00 59 00 } //1 TH3RULER_KEY
		$a_01_1 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 41 00 4d 00 2e 00 64 00 61 00 74 00 } //1 \AppData\Roaming\Microsoft\Windows\CAM.dat
		$a_01_2 = {2f 00 57 00 65 00 62 00 63 00 61 00 6d 00 5f 00 53 00 68 00 6f 00 74 00 73 00 2f 00 } //1 /Webcam_Shots/
		$a_01_3 = {4c 00 4f 00 47 00 49 00 4e 00 5f 00 44 00 41 00 54 00 41 00 5f 00 44 00 4f 00 57 00 4e 00 4c 00 4f 00 41 00 44 00 5f 00 57 00 4f 00 52 00 4b 00 45 00 52 00 } //1 LOGIN_DATA_DOWNLOAD_WORKER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}