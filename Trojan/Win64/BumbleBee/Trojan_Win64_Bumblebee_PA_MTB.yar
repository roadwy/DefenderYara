
rule Trojan_Win64_Bumblebee_PA_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 01 81 b8 03 00 00 49 8b [0-02] 08 49 8b [0-02] 70 02 00 00 48 69 88 40 01 00 00 [0-04] 48 31 8a d0 03 00 00 4d 8b [0-02] 58 04 00 00 49 63 [0-02] 0c 06 00 00 49 63 [0-02] 08 06 00 00 41 8b 0c 80 41 31 0c 90 90 41 8b [0-02] 1c 06 00 00 23 ?? 7d } //1
		$a_01_1 = {4f 62 6f 58 62 51 58 4d 50 42 } //1 OboXbQXMPB
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Bumblebee_PA_MTB_2{
	meta:
		description = "Trojan:Win64/Bumblebee.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 49 ?? 41 0f b6 14 00 49 83 c0 04 49 8b 81 ?? ?? ?? ?? 0f af d1 49 63 49 ?? 88 14 01 b8 ?? ?? ?? ?? 41 2b 41 ?? 41 01 81 ?? ?? ?? ?? b8 ?? ?? ?? ?? 41 8b } //10
		$a_03_1 = {41 33 ca 41 ff 41 ?? 2b c1 41 01 41 ?? 41 8b 41 ?? 83 f0 01 83 c0 df 03 c2 41 2b 91 ?? ?? ?? ?? 41 01 81 ?? ?? ?? ?? 83 ea ?? 41 8b 41 } //1
		$a_03_2 = {41 8b ca 41 33 89 ?? ?? ?? ?? 41 ff 41 50 2b c1 41 01 41 ?? 41 8b 41 ?? 83 f0 01 83 c0 df 03 c2 41 2b 91 ?? ?? ?? ?? 41 01 81 ?? ?? ?? ?? 83 ea ?? 41 8b 41 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}