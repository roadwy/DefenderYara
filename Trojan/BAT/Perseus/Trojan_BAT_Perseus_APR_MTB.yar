
rule Trojan_BAT_Perseus_APR_MTB{
	meta:
		description = "Trojan:BAT/Perseus.APR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c 08 16 72 ?? ?? ?? 70 a2 00 08 17 7e 07 00 00 04 a2 00 08 18 72 ?? ?? ?? 70 a2 00 08 19 28 ?? ?? ?? 0a a2 00 08 1a 72 } //2
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_2 = {43 00 4d 00 44 00 72 00 53 00 68 00 65 00 6c 00 6c 00 53 00 54 00 55 00 42 00 } //1 CMDrShellSTUB
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}