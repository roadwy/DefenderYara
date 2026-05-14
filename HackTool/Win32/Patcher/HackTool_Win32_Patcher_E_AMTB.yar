
rule HackTool_Win32_Patcher_E_AMTB{
	meta:
		description = "HackTool:Win32/Patcher.E!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4b 45 59 48 41 43 4b 45 44 42 59 53 56 45 4e 53 4b 54 45 41 4d 50 48 52 4f 5a 45 4e 48 45 4c 4c } //KEYHACKEDBYSVENSKTEAMPHROZENHELL  1
		$a_80_1 = {53 76 65 6e 73 4b 20 5b 74 45 61 4d 20 70 48 72 4f 7a 45 6e 20 48 65 4c 4c 5d } //SvensK [tEaM pHrOzEn HeLL]  1
		$a_80_2 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 56 61 6e 44 79 6b 65 5c 53 65 63 75 72 65 43 52 54 5c 4c 69 63 65 6e 73 65 } //HKEY_LOCAL_MACHINE\SOFTWARE\VanDyke\SecureCRT\License  1
		$a_80_3 = {41 70 70 6c 79 20 70 61 74 63 68 20 61 6e 64 20 65 6e 6a 6f 79 2e } //Apply patch and enjoy.  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}