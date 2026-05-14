
rule Trojan_Win64_Disco_MKA_MTB{
	meta:
		description = "Trojan:Win64/Disco.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 63 72 65 65 6e 2e 73 63 72 65 65 6e 73 68 6f 74 5f 63 61 70 74 75 72 65 } //10 screen.screenshot_capture
		$a_01_1 = {53 74 61 72 74 69 6e 67 20 6b 65 79 6c 6f 67 20 6d 6f 6e 69 74 6f 72 } //5 Starting keylog monitor
		$a_01_2 = {72 65 71 75 65 73 74 5f 61 75 64 69 6f 5f 64 65 76 69 63 65 73 } //3 request_audio_devices
		$a_01_3 = {63 61 70 74 75 72 65 4c 6f 6f 70 3a 20 4a 50 45 47 20 65 6e 63 6f 64 69 6e 67 20 66 61 69 6c 65 64 20 28 65 6d 70 74 79 29 } //2 captureLoop: JPEG encoding failed (empty)
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=20
 
}