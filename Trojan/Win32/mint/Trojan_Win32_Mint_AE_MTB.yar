
rule Trojan_Win32_Mint_AE_MTB{
	meta:
		description = "Trojan:Win32/Mint.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 d0 c7 00 5c 35 6b 69 c7 40 04 64 52 6f 30 c7 40 08 74 2e 65 78 66 c7 40 0c 65 00 c7 44 24 08 00 00 00 00 8d 85 ?? ?? ff ff 89 44 24 04 8d 85 } //1
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}