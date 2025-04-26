
rule BrowserModifier_Win32_Nassem{
	meta:
		description = "BrowserModifier:Win32/Nassem,SIGNATURE_TYPE_PEHSTR,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6f 42 48 4f 45 76 65 6e 74 } //3 DoBHOEvent
		$a_01_1 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //3 䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_2 = {43 00 4f 00 4e 00 46 00 49 00 47 00 55 00 52 00 41 00 54 00 4f 00 52 00 5f 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 5f 00 4c 00 4f 00 43 00 4b 00 } //1 CONFIGURATOR_GLOBAL_LOCK
		$a_01_3 = {4d 00 41 00 58 00 46 00 65 00 65 00 64 00 55 00 52 00 4c 00 } //1 MAXFeedURL
		$a_01_4 = {6d 00 65 00 73 00 73 00 61 00 6e 00 67 00 65 00 72 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 6e 00 65 00 74 00 2f 00 63 00 6f 00 6e 00 66 00 } //2 messangerupdate.net/conf
		$a_01_5 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 2e 00 64 00 6c 00 6c 00 } //2 \Drivers\pub.dll
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=9
 
}