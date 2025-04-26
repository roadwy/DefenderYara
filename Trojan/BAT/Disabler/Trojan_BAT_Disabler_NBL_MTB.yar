
rule Trojan_BAT_Disabler_NBL_MTB{
	meta:
		description = "Trojan:BAT/Disabler.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {08 1b 62 08 58 11 04 61 0c 11 05 18 58 49 13 04 11 04 39 1d 00 00 00 09 1b 62 09 58 11 04 61 0d 11 05 18 d3 18 5a 58 13 05 11 05 49 25 13 04 3a cc ff ff ff } //1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 46 65 61 74 75 72 65 73 } //SOFTWARE\Microsoft\Windows Defender\Features  1
		$a_80_2 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 5c 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications  1
		$a_80_3 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 } //SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}