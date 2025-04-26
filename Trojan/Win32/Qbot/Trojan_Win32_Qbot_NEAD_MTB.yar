
rule Trojan_Win32_Qbot_NEAD_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 75 74 5c 62 69 6e 61 72 69 65 73 5c 78 38 36 72 65 74 5c 62 69 6e 5c 69 33 38 36 5c 47 72 61 70 68 69 63 73 5c 64 78 74 65 78 2e 70 64 62 } //5 out\binaries\x86ret\bin\i386\Graphics\dxtex.pdb
		$a_01_1 = {2f 00 67 00 41 00 4d 00 41 00 2f 00 49 00 6d 00 61 00 67 00 65 00 47 00 61 00 6d 00 6d 00 61 00 } //2 /gAMA/ImageGamma
		$a_01_2 = {52 6f 6e 76 65 72 74 50 69 78 65 6c 46 6f 72 6d 61 74 } //1 RonvertPixelFormat
		$a_01_3 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}