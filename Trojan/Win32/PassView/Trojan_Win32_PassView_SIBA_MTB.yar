
rule Trojan_Win32_PassView_SIBA_MTB{
	meta:
		description = "Trojan:Win32/PassView.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3c 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 56 61 75 6c 74 5c 34 42 46 34 43 34 34 32 2d 39 42 38 41 2d 34 31 41 30 2d 42 33 38 30 2d 44 44 34 41 37 30 34 44 44 42 32 } //5 AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB2
		$a_00_1 = {22 41 63 63 6f 75 6e 74 22 2c 22 4c 6f 67 69 6e 20 4e 61 6d 65 22 2c 22 50 61 73 73 77 6f 72 64 22 2c 22 57 65 62 20 53 69 74 65 22 2c 22 43 6f 6d 6d 65 6e 74 73 22 } //5 "Account","Login Name","Password","Web Site","Comments"
		$a_00_2 = {69 65 70 76 5f 73 69 74 65 73 2e 74 78 74 } //1 iepv_sites.txt
		$a_03_3 = {33 db 88 1f 8a 06 90 18 84 c0 90 18 b1 ?? 2a cb 32 c8 6a ?? 8d 45 ?? 50 80 f1 ?? 57 88 4d 90 1b 04 e8 ?? ?? ?? ?? 83 c4 0c 43 8a 04 33 84 c0 75 } //50
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_03_3  & 1)*50) >=60
 
}