
rule Trojan_Win32_CobaltStrike_CM_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 83 c1 90 01 01 89 4d 90 01 01 8b 55 90 01 01 3b 55 90 01 01 73 90 01 01 8b 45 90 01 01 25 90 01 04 79 90 01 01 48 0d 90 01 04 40 88 45 90 01 01 0f b6 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f be 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CobaltStrike_CM_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {66 a1 f2 0a 4a 00 66 0f af c7 66 a3 90 02 04 a1 90 02 04 0f af c7 69 c0 90 02 04 66 a3 90 02 04 0f b7 c0 0f af c1 03 c7 a3 90 02 04 2b d3 2b d5 5f 83 ea 90 02 01 5d 0f b7 c2 5b 59 c3 90 00 } //1
		$a_00_1 = {69 00 6e 00 63 00 68 00 } //1 inch
		$a_01_2 = {62 72 6f 6b 65 6e 20 70 69 70 65 } //1 broken pipe
		$a_01_3 = {6f 77 6e 65 72 20 64 65 61 64 } //1 owner dead
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}