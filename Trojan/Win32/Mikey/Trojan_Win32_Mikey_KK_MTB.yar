
rule Trojan_Win32_Mikey_KK_MTB{
	meta:
		description = "Trojan:Win32/Mikey.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 8d 44 24 2c 50 ff 15 } //20
		$a_01_1 = {5c 64 6f 65 6e 65 72 69 75 6d 2d 6d 61 69 6e 5c 65 6c 65 63 74 72 6f 6e 5c 6e 6f 64 65 5f 6d 6f 64 75 6c 65 73 5c 62 6f 75 6b 69 61 70 69 5c 62 75 69 6c 64 5c 52 65 6c 65 61 73 65 5c 71 7a 65 73 63 6d 6f 6d 7a 79 77 6e 2e 70 64 62 } //10 \doenerium-main\electron\node_modules\boukiapi\build\Release\qzescmomzywn.pdb
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}