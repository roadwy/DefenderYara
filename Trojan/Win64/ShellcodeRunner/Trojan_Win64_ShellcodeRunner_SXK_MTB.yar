
rule Trojan_Win64_ShellcodeRunner_SXK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 50 e8 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8d 85 f0 fc ff ff 83 c4 18 68 ?? ?? ?? ?? 50 ff d7 8d 85 f0 fc ff ff 50 ff 15 } //30
		$a_03_1 = {c6 45 fc 13 8b 85 ?? fd ff ff ff 36 50 8b 08 ff 51 2c 89 85 ?? fd ff ff 83 c9 ff c6 45 fc 01 f0 0f c1 4e ?? 49 75 37 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}