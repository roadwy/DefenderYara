
rule Trojan_Win64_VidarStealer_RHB_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.RHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 2c } //1
		$a_01_1 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //2 \ProgramData\
		$a_01_2 = {42 72 6f 77 73 65 72 20 4c 69 73 74 } //2 Browser List
		$a_01_3 = {43 68 72 6f 6d 69 75 6d 20 50 6c 75 67 69 6e 73 } //2 Chromium Plugins
		$a_01_4 = {46 69 72 65 66 6f 78 20 50 6c 75 67 69 6e 73 } //2 Firefox Plugins
		$a_01_5 = {57 61 6c 6c 65 74 20 52 75 6c 65 73 } //2 Wallet Rules
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=11
 
}