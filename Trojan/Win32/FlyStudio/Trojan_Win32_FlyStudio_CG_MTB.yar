
rule Trojan_Win32_FlyStudio_CG_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c4 18 6a 00 6a 00 6a 00 68 01 00 01 00 68 00 00 01 06 68 01 00 01 52 68 02 00 00 00 bb } //01 00 
		$a_01_1 = {6c 6a 2e 62 61 74 } //01 00  lj.bat
		$a_01_2 = {75 73 65 72 2e 71 7a 6f 6e 65 2e 71 71 2e 63 6f 6d 2f 31 32 33 39 31 38 31 37 31 32 } //01 00  user.qzone.qq.com/1239181712
		$a_01_3 = {64 65 6c 20 2f 66 20 2f 71 20 25 75 73 65 72 70 72 6f 66 69 6c 65 25 5c 63 6f 6f 6b 69 65 73 5c 2a 2e 2a } //01 00  del /f /q %userprofile%\cookies\*.*
		$a_01_4 = {77 77 77 2e 63 66 79 75 65 66 65 69 2e 63 6f 6d 2f 78 69 61 7a 61 69 2e 68 74 6d 6c } //01 00  www.cfyuefei.com/xiazai.html
		$a_01_5 = {76 6d 69 70 2e 74 61 6f 62 61 6f 2e 63 6f 6d } //01 00  vmip.taobao.com
		$a_01_6 = {77 77 77 2e 6c 6f 67 6f 31 39 33 2e 63 6f 6d } //01 00  www.logo193.com
		$a_01_7 = {43 3a 5c 77 65 6e 62 65 6e 2e 74 78 74 } //00 00  C:\wenben.txt
	condition:
		any of ($a_*)
 
}