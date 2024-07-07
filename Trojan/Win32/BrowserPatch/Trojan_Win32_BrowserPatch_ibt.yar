
rule Trojan_Win32_BrowserPatch_ibt{
	meta:
		description = "Trojan:Win32/BrowserPatch!ibt,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 54 65 6e 63 65 6e 74 5c 51 51 5c } //1 \AppData\Roaming\Tencent\QQ\
		$a_01_1 = {fc 68 32 74 91 0c 8b f4 8d 7e f4 33 db b7 04 2b e3 33 d2 64 8b 4a 30 8b 49 0c 8b 49 1c 8b 69 08 8b 59 20 8b 09 66 39 53 18 75 f2 ad } //1
		$a_01_2 = {60 8b 45 3c 8b 4c 05 78 03 cd 8b 59 20 03 dd 33 ff 47 8b 34 bb 03 f5 99 0f be 06 3a c4 74 08 c1 ca 07 03 d0 46 eb f1 3b 54 24 1c 75 e4 8b 59 24 03 dd 66 8b 3c 7b 8b 59 1c 03 dd 03 2c bb 64 e8 00 00 00 00 58 83 c0 0c 50 ff d5 e9 c4 58 f4 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}