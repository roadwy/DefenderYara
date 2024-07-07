
rule Trojan_Win32_ShellcodeRunner_EK_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 84 35 d0 fd ff ff 88 8c 35 d0 fd ff ff 0f b6 c8 88 84 3d d0 fd ff ff 0f b6 84 35 d0 fd ff ff 03 c8 0f b6 c1 8b 8d d8 fe ff ff 0f b6 84 05 d0 fd ff ff 32 44 13 08 88 04 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}