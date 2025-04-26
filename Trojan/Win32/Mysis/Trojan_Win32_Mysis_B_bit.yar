
rule Trojan_Win32_Mysis_B_bit{
	meta:
		description = "Trojan:Win32/Mysis.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 64 6f 73 2e 74 66 } //1 ddos.tf
		$a_01_1 = {57 69 6e 64 6f 77 73 20 48 65 6c 70 20 53 79 73 74 65 6d 20 4d 79 73 73 } //1 Windows Help System Myss
		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 2e 65 78 65 } //1 %c%c%c%c%c.exe
		$a_03_3 = {56 ff 15 74 b4 41 00 8b f0 e8 ?? ?? ?? ?? 83 c0 03 33 d2 0f af c6 f7 74 24 08 5e 8b c2 } //1
		$a_03_4 = {6a 12 56 53 e8 ?? ?? ?? ?? c6 85 ?? ?? ff ff 47 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 57 c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6e c6 85 ?? ?? ff ff 64 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 77 c6 85 ?? ?? ff ff 73 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2) >=5
 
}