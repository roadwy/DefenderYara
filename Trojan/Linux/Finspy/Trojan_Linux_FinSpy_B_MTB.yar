
rule Trojan_Linux_FinSpy_B_MTB{
	meta:
		description = "Trojan:Linux/FinSpy.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 c7 85 88 8b ff ff ff ff ff ff 48 89 c2 b8 00 00 00 00 48 8b 8d 88 8b ff ff 48 89 d7 f2 ae 48 89 c8 48 f7 d0 48 83 e8 01 89 c3 48 8d 85 e0 8b ff ff 48 c7 85 88 8b ff ff ff ff ff ff 48 89 c2 b8 00 00 00 00 48 8b 8d 88 8b ff ff 48 89 d7 f2 ae 48 89 c8 48 f7 d0 48 8d 50 ff 48 8d 8d e0 8b ff ff 8b 85 c4 8b ff ff 48 89 ce 89 c7 e8 27 d8 ff ff 89 85 c8 8b ff ff 3b 9d c8 8b ff ff 0f 95 c0 84 c0 74 22 c7 85 b8 8b ff ff db ff ff ff 8b 85 c4 8b ff ff 89 c7 } //1
		$a_01_1 = {25 73 2f 2e 6b 64 65 2f 41 75 74 6f 73 74 61 72 74 2f 75 64 65 76 32 2e 73 68 } //1 %s/.kde/Autostart/udev2.sh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}