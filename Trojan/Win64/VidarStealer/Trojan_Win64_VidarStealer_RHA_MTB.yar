
rule Trojan_Win64_VidarStealer_RHA_MTB{
	meta:
		description = "Trojan:Win64/VidarStealer.RHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_03_0 = {50 45 00 00 64 86 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 02 0e 2c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 a0 0c } //1
		$a_01_1 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //2 \ProgramData\
		$a_01_2 = {5c 4e 65 74 77 6f 72 6b 5c 43 6f 6f 6b 69 65 73 } //2 \Network\Cookies
		$a_01_3 = {66 69 72 65 66 6f 78 } //2 firefox
		$a_01_4 = {63 68 72 6f 6d 65 2e 64 6c 6c } //2 chrome.dll
		$a_01_5 = {5c 6b 65 79 34 2e 64 62 } //2 \key4.db
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=11
 
}