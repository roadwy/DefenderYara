
rule Worm_BAT_FileCoder_AC_AMTB{
	meta:
		description = "Worm:BAT/FileCoder.AC!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 65 70 6c 6f 79 53 70 79 77 61 72 65 } //DeploySpyware  1
		$a_80_1 = {54 52 55 45 57 30 52 4d 2e 70 64 62 } //TRUEW0RM.pdb  1
		$a_80_2 = {73 74 61 72 74 20 54 72 75 65 57 6f 72 6d } //start TrueWorm  1
		$a_80_3 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 72 75 65 57 6f 72 6d } //HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrueWorm  1
		$a_80_4 = {57 69 46 69 20 43 72 65 64 65 6e 74 69 61 6c 73 } //WiFi Credentials  1
		$a_80_5 = {54 52 55 45 5f 57 30 52 4d 5f 41 43 54 49 56 41 54 45 44 20 26 26 20 65 63 68 6f 20 53 59 53 54 45 4d 20 45 4e 43 52 59 50 54 45 44 20 26 26 20 65 63 68 6f 20 44 41 54 41 20 53 54 4f 4c 45 4e 20 41 4e 44 20 53 45 4e 54 } //TRUE_W0RM_ACTIVATED && echo SYSTEM ENCRYPTED && echo DATA STOLEN AND SENT  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}