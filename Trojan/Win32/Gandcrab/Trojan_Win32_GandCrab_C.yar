
rule Trojan_Win32_GandCrab_C{
	meta:
		description = "Trojan:Win32/GandCrab.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 85 58 ff ff ff 78 cd b3 64 c7 85 90 fd ff ff 4f 3a 6d 4f c7 85 60 ff ff ff dd 16 f9 1c c7 85 94 fc ff ff 00 41 2c 4b c7 85 68 ff ff ff 5f 3a bf 7c c7 85 70 ff ff ff 87 48 fb 56 c7 85 78 ff ff ff d8 2e b2 2a } //1
		$a_01_1 = {76 6f 6b 6f 67 75 6d 69 77 75 62 6f 74 61 20 68 75 74 75 63 6f 7a 61 20 6d 65 76 69 6a 69 68 61 72 61 } //1 vokogumiwubota hutucoza mevijihara
		$a_01_2 = {62 65 6d 65 62 6f 70 6f 62 6f 7a 65 68 61 72 75 70 75 79 75 63 69 20 74 65 66 75 76 75 6b 75 79 69 64 65 64 69 79 65 6a 75 79 69 77 61 64 75 74 6f 78 61 7a 65 70 61 20 79 75 77 65 6e 65 73 69 68 75 68 6f 73 69 63 65 66 75 6c 65 63 75 } //1 bemebopobozeharupuyuci tefuvukuyidediyejuyiwadutoxazepa yuwenesihuhosicefulecu
		$a_01_3 = {f7 e9 03 d1 c1 fa 04 8b c2 c1 e8 1f 03 c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}