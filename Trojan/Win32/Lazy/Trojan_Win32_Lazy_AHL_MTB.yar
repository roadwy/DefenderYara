
rule Trojan_Win32_Lazy_AHL_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 56 20 4b 69 6c 6c 65 72 20 4f 4e } //10 AV Killer ON
		$a_01_1 = {43 68 65 63 6b 20 74 68 69 73 20 74 6f 20 45 6e 61 62 6c 65 20 74 68 65 20 41 6e 74 69 2d 56 69 72 75 73 20 4b 69 6c 6c 65 72 20 6f 70 74 69 6f 6e } //20 Check this to Enable the Anti-Virus Killer option
		$a_01_2 = {43 68 65 63 6b 20 74 68 69 73 20 74 6f 20 63 68 61 6e 67 65 20 74 68 65 20 69 63 6f 6e 20 6f 66 20 74 68 65 20 6f 75 74 70 75 74 20 66 69 6c 65 } //30 Check this to change the icon of the output file
		$a_01_3 = {43 72 79 70 74 20 74 68 65 20 66 69 6c 65 } //40 Crypt the file
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}