
rule Trojan_Win32_Keylogger_PGL_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 79 00 73 00 70 00 72 00 6f 00 63 00 2e 00 65 00 78 00 65 00 } //1 \sysproc.exe
		$a_80_1 = {38 30 38 38 35 39 35 32 30 31 3a 41 41 47 71 6e 37 58 7a 42 73 59 30 74 39 76 42 44 65 39 68 4b 75 53 64 63 76 32 44 56 46 6f 74 69 43 67 } //8088595201:AAGqn7XzBsY0t9vBDe9hKuSdcv2DVFotiCg  2
		$a_80_2 = {2f 73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d } ///sendMessage?chat_id=  2
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=5
 
}