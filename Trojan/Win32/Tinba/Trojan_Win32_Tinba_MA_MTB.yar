
rule Trojan_Win32_Tinba_MA_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 85 60 ff ff ff 8d 4d a0 b2 00 8a b5 57 ff ff ff 80 f6 02 88 b5 57 ff ff ff 2a 95 4f ff ff ff 89 0c 24 89 44 24 04 8b 85 08 ff ff ff 89 44 24 08 88 95 f7 fe ff ff e8 3c bd ff ff 8b 4d 88 8a 95 57 ff ff ff 80 ca 6e 8a b5 f7 fe ff ff 88 b5 4f ff ff ff 88 95 57 ff ff ff 8b b5 1c ff ff ff 39 f1 89 85 f0 fe ff ff 0f 85 } //10
		$a_01_1 = {43 72 65 61 74 65 4d 61 69 6c 73 6c 6f 74 57 47 65 74 54 69 63 6b 43 6f 75 6d } //1 CreateMailslotWGetTickCoum
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Tinba_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Tinba.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 34 03 44 24 24 8b 4c 24 14 8a 04 10 8b 54 24 24 2b cf 88 04 11 ff 44 24 24 8b 44 24 24 3b 44 24 4c 0f 8c } //1
		$a_01_1 = {44 65 74 65 63 74 65 64 20 6d 65 6d 6f 72 79 20 6c 65 61 6b 73 21 } //1 Detected memory leaks!
		$a_01_2 = {50 6f 73 74 51 75 69 74 4d 65 73 73 61 67 65 } //1 PostQuitMessage
		$a_01_3 = {43 72 65 61 74 65 53 74 64 41 63 63 65 73 73 69 62 6c 65 50 72 6f 78 79 41 } //1 CreateStdAccessibleProxyA
		$a_01_4 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}