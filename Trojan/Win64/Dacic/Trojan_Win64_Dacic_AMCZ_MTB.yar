
rule Trojan_Win64_Dacic_AMCZ_MTB{
	meta:
		description = "Trojan:Win64/Dacic.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 35 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 1d } //5
		$a_80_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 77 69 72 65 73 68 61 72 6b 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //taskkill /FI "IMAGENAME eq wireshark*" /IM * /F /T >nul 2>&1  2
		$a_80_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 70 72 6f 63 65 73 73 68 61 63 6b 65 72 2a 22 20 2f 49 4d 20 2a 20 2f 46 20 2f 54 20 3e 6e 75 6c 20 32 3e 26 31 } //taskkill /FI "IMAGENAME eq processhacker*" /IM * /F /T >nul 2>&1  2
		$a_80_3 = {73 63 20 73 74 6f 70 20 4b 50 72 6f 63 65 73 73 48 61 63 6b 65 72 32 20 3e 6e 75 6c 20 32 3e 26 31 } //sc stop KProcessHacker2 >nul 2>&1  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1) >=10
 
}