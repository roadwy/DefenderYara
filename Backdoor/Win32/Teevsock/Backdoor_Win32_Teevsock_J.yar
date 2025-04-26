
rule Backdoor_Win32_Teevsock_J{
	meta:
		description = "Backdoor:Win32/Teevsock.J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7d 33 8b 45 08 03 45 f0 0f be 08 8b 55 10 33 55 f8 33 ca 8b 45 08 03 45 f0 88 08 83 7d f8 04 7e 09 } //1
		$a_01_1 = {42 53 2d 44 65 66 65 6e 64 65 72 00 } //1 卂䐭晥湥敤r
		$a_01_2 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 52 41 53 53 20 53 65 72 76 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}