
rule Trojan_Win32_FlyStudio_NT_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 89 47 ?? 75 05 e8 1f 46 ff ff 8b 03 8b c8 69 c9 ?? ?? ?? ?? 03 4e 0c c1 e1 ?? 51 8b 4f 0c 6a ?? 8d 04 81 50 e8 f0 91 fe ff 8b 46 0c 83 c4 ?? 89 03 57 ff 36 } //5
		$a_01_1 = {64 79 77 74 2e 63 6f 6d 2e 63 6e } //1 dywt.com.cn
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}