
rule Trojan_BAT_Xmrig_GCE_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.GCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {55 30 68 46 54 45 77 6b } //U0hFTEwk  01 00 
		$a_80_1 = {55 30 68 46 54 45 77 6c } //U0hFTEwl  01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_3 = {63 34 35 37 36 30 64 39 36 35 63 33 64 62 65 39 65 61 36 31 34 39 32 32 35 39 63 33 33 62 39 63 62 } //01 00  c45760d965c3dbe9ea61492259c33b9cb
		$a_01_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  set_UseShellExecute
		$a_01_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_6 = {53 00 48 00 45 00 4c 00 4c 00 2e 00 65 00 78 00 65 00 } //00 00  SHELL.exe
	condition:
		any of ($a_*)
 
}