
rule TrojanDropper_Win32_Injector_F{
	meta:
		description = "TrojanDropper:Win32/Injector.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {8a 08 88 0f 47 40 d1 6d 08 ff 4d 90 01 01 eb 90 00 } //1
		$a_02_1 = {83 e9 0a c6 45 90 01 01 e8 c6 45 90 01 01 6a ff 75 08 c6 45 90 01 01 e8 89 90 01 02 ff 55 90 00 } //3
		$a_00_2 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 2e 65 78 65 } //1 Internet Explorer\ie.exe
		$a_00_3 = {52 73 69 6e 67 53 63 61 6e } //1 RsingScan
		$a_00_4 = {2d 69 6e 73 74 61 6c 6c 20 22 25 73 22 } //1 -install "%s"
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}