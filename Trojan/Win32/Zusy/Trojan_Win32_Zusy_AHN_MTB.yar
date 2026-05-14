
rule Trojan_Win32_Zusy_AHN_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 25 73 5c 64 79 77 69 7a 61 72 64 2e 65 78 65 22 20 2d 64 6f 79 6f } //10 "%s\dywizard.exe" -doyo
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 44 6f 75 79 6f 75 5c 53 65 74 74 69 6e 67 73 } //20 Software\Douyou\Settings
		$a_01_2 = {64 79 70 6c 75 67 69 6e 32 2e 64 6c 6c } //30 dyplugin2.dll
		$a_01_3 = {25 73 5c 64 6f 79 6f 73 74 61 72 74 2e 65 78 65 } //40 %s\doyostart.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}