
rule Trojan_Win64_Stealer_AHD_MTB{
	meta:
		description = "Trojan:Win64/Stealer.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 22 63 6d 64 20 2f 63 20 25 50 52 4f 47 52 41 4d 44 41 54 41 25 5c 22 2c 20 30 2c 20 46 61 6c 73 65 } //30 WshShell.Run "cmd /c %PROGRAMDATA%\", 0, False
		$a_01_1 = {74 65 6d 70 4d 61 6c 66 6f 72 6d 65 64 20 73 69 7a 65 5f 68 69 6e 74 } //20 tempMalformed size_hint
		$a_01_2 = {74 61 73 6b 6c 69 73 74 61 76 67 73 76 63 2e 65 78 65 61 76 61 73 74 75 69 2e 65 78 65 61 76 61 73 74 73 76 63 2e 65 78 65 73 72 63 5c 6d 61 69 6e 2e 72 73 } //10 tasklistavgsvc.exeavastui.exeavastsvc.exesrc\main.rs
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}