
rule Trojan_Win32_DarkComet_AKD_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 6e 74 75 73 65 6d 65 2e 63 74 38 2e 70 6c } //5 dontuseme.ct8.pl
		$a_01_1 = {63 6d 64 20 2f 63 20 73 63 20 64 65 6c 65 74 65 20 49 6e 74 65 6c 47 70 75 55 70 64 61 74 65 72 20 26 26 20 63 6d 64 20 2f 63 20 73 63 20 73 74 6f 70 20 49 6e 74 65 6c 47 70 75 55 70 64 61 74 65 72 } //4 cmd /c sc delete IntelGpuUpdater && cmd /c sc stop IntelGpuUpdater
		$a_01_2 = {55 6e 61 62 6c 65 20 74 6f 20 72 65 61 63 68 20 74 68 65 20 73 65 72 76 65 72 } //1 Unable to reach the server
		$a_01_3 = {50 6c 65 61 73 65 20 72 65 73 74 61 72 74 20 79 6f 75 72 20 72 6f 75 74 65 72 20 6f 72 20 79 6f 75 72 20 50 43 20 74 6f 20 6d 61 6b 65 20 73 75 72 65 20 69 74 27 73 20 63 6f 6e 6e 65 63 74 65 64 20 74 6f 20 74 68 65 20 69 6e 74 65 72 6e 65 74 } //2 Please restart your router or your PC to make sure it's connected to the internet
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=12
 
}