
rule HackTool_iPhoneOS_IosJailbreak_A_MTB{
	meta:
		description = "HackTool:iPhoneOS/IosJailbreak.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 2f 70 77 6e 65 64 34 2f 44 6f 77 6e 6c 6f 61 64 73 2f 54 68 30 72 5f 46 72 65 79 61 2d 6d 61 69 6e 2f 54 48 30 52 2f 65 78 70 6c 6f 69 74 73 } //1 Users/pwned4/Downloads/Th0r_Freya-main/TH0R/exploits
		$a_01_1 = {73 68 6f 67 75 6e 70 77 6e 64 } //1 shogunpwnd
		$a_01_2 = {2f 76 61 72 2f 72 75 6e 2f 70 73 70 61 77 6e 5f 68 6f 6f 6b 2e 74 73 } //1 /var/run/pspawn_hook.ts
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}