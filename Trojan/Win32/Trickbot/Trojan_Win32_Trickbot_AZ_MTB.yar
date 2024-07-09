
rule Trojan_Win32_Trickbot_AZ_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a c3 2a 44 24 ?? 83 c4 04 32 03 51 32 44 24 ?? 52 88 03 } //1
		$a_01_1 = {6a 6f 65 62 6f 78 63 6f 6e 74 72 6f 6c 2e 65 78 65 } //1 joeboxcontrol.exe
		$a_01_2 = {78 33 32 64 62 67 2e 65 78 65 } //1 x32dbg.exe
		$a_01_3 = {43 68 65 63 6b 69 6e 67 20 70 72 6f 63 65 73 73 20 6f 66 20 6d 61 6c 77 61 72 65 20 61 6e 61 6c 79 73 69 73 20 74 6f 6f 6c } //1 Checking process of malware analysis tool
		$a_01_4 = {68 65 6c 6c 6f 20 68 65 61 76 65 6e } //1 hello heaven
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}