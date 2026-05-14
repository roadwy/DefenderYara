
rule Trojan_Win32_Runner_HAB_MTB{
	meta:
		description = "Trojan:Win32/Runner.HAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 61 74 2e 62 61 74 } //2 bat.bat
		$a_81_1 = {62 69 6e 2e 73 66 78 2e 65 78 65 } //2 bin.sfx.exe
		$a_81_2 = {76 62 73 2e 76 62 73 } //2 vbs.vbs
		$a_81_3 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 62 61 74 2e 62 61 74 22 2c 20 30 2c 20 66 61 6c 73 65 } //5 WshShell.Run "cmd.exe /c bat.bat", 0, false
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*5) >=11
 
}