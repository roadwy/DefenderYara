
rule Trojan_Win64_Tedy_GPBX_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GPBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 20 2f 46 } //1 taskkill /IM ProcessHacker.exe /F
		$a_81_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 64 6e 53 70 79 2e 65 78 65 20 2f 46 } //1 taskkill /IM dnSpy.exe /F
		$a_81_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 63 68 65 61 74 65 6e 67 69 6e 65 2d 78 38 36 5f 36 34 2e 65 78 65 20 2f 46 } //1 taskkill /IM cheatengine-x86_64.exe /F
		$a_81_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 6f 6c 6c 79 64 62 67 2e 65 78 65 20 2f 46 } //1 taskkill /IM ollydbg.exe /F
		$a_81_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 69 64 61 36 34 2e 65 78 65 20 2f 46 } //1 taskkill /IM ida64.exe /F
		$a_81_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 78 36 34 64 62 67 2e 65 78 65 20 2f 46 } //1 taskkill /IM x64dbg.exe /F
		$a_81_6 = {53 74 6f 70 20 64 65 62 75 67 67 69 6e 67 } //1 Stop debugging
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}