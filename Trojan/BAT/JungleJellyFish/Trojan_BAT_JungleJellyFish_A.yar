
rule Trojan_BAT_JungleJellyFish_A{
	meta:
		description = "Trojan:BAT/JungleJellyFish.A,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 61 73 74 5a 69 70 } //5 FastZip
		$a_01_1 = {45 78 74 72 61 63 74 5a 69 70 } //5 ExtractZip
		$a_00_2 = {6f 75 74 2e 65 78 65 } //1 out.exe
		$a_00_3 = {64 6c 2e 7a 69 70 } //1 dl.zip
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f 67 72 61 70 68 79 } //SOFTWARE\Microsoft\Cryptography  5
		$a_80_5 = {4d 61 63 68 69 6e 65 47 75 69 64 } //MachineGuid  5
		$a_00_6 = {57 65 62 56 69 65 77 32 } //5 WebView2
		$a_80_7 = {70 72 65 6d 69 75 6d 6c 69 63 65 6e 73 65 63 68 65 63 6b 2e 63 6f 6d } //premiumlicensecheck.com  5
		$a_00_8 = {6f 70 65 6e 2e 75 73 65 72 6d 61 6e 75 61 6c 76 61 75 6c 74 2e 63 6f 6d } //1 open.usermanualvault.com
		$a_02_9 = {03 04 14 6f 90 09 0c 00 73 ?? ?? ?? ?? 25 05 6f } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_00_6  & 1)*5+(#a_80_7  & 1)*5+(#a_00_8  & 1)*1+(#a_02_9  & 1)*5) >=35
 
}