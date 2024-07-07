
rule Trojan_Win32_DarkCloud_GZA_MTB{
	meta:
		description = "Trojan:Win32/DarkCloud.GZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d0 8d 4d 90 01 01 ff d6 ba 90 01 04 8d 4d 94 ff d7 8b 55 90 01 01 89 5d 90 01 01 8d 4d 98 ff d6 8d 4d 94 51 8d 55 98 52 90 00 } //10
		$a_80_1 = {43 68 72 6f 6d 65 4d 65 74 61 4d 61 73 6b 56 61 75 6c 74 44 61 74 61 2e 74 78 74 } //ChromeMetaMaskVaultData.txt  1
		$a_80_2 = {44 41 52 4b 43 4c 4f 55 44 } //DARKCLOUD  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}