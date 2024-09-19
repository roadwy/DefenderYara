
rule Trojan_Win32_Malex_ASG_MTB{
	meta:
		description = "Trojan:Win32/Malex.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {ba 02 00 00 00 8a 84 15 ?? ?? ff ff 84 c0 74 22 8a 8d ?? ?? ff ff 32 8d ?? ?? ff ff 80 c9 50 30 c1 88 8c 15 ?? ?? ff ff 42 eb } //3
		$a_03_1 = {85 c0 89 85 ?? fb ff ff 19 c0 f7 d8 8d 85 ?? fb ff ff 6a 10 50 ff b5 } //2
		$a_01_2 = {7b 25 30 34 58 2d 38 42 39 41 2d 31 31 44 35 2d 45 42 41 31 2d 46 37 38 45 45 45 45 45 45 39 38 33 7d } //1 {%04X-8B9A-11D5-EBA1-F78EEEEEE983}
		$a_01_3 = {25 64 20 70 72 6f 63 65 73 73 65 73 20 6b 69 6c 6c 65 64 20 4f 4b } //1 %d processes killed OK
		$a_01_4 = {72 65 62 6f 6f 74 } //1 reboot
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}