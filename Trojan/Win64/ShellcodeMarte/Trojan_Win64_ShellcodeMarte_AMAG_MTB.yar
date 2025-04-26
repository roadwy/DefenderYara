
rule Trojan_Win64_ShellcodeMarte_AMAG_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeMarte.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b d3 48 8b c8 48 8b f8 4c 89 6c 24 20 ff 15 ?? ?? ?? ?? 48 8b cf ff 15 ?? ?? ?? ?? b9 60 ea 00 00 ff 15 } //2
		$a_03_1 = {99 83 e2 1f 03 c2 c1 f8 05 0f af c3 c1 e0 02 8b f8 8d 48 36 89 4d c1 b9 ?? ?? ?? ?? 66 89 4d bf 8b c8 } //2
		$a_80_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 71 75 69 63 6b 53 63 72 65 65 6e 53 68 6f 74 } //Application Data\quickScreenShot  1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}