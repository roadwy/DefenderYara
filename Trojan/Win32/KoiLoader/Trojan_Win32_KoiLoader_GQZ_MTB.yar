
rule Trojan_Win32_KoiLoader_GQZ_MTB{
	meta:
		description = "Trojan:Win32/KoiLoader.GQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c8 83 e1 0f 8a 0c 31 30 0c 07 40 3b c2 72 f0 } //10
		$a_80_1 = {5c 4a 61 78 78 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 77 61 6c 6c 65 74 2e 64 61 74 } //\Jaxx\Local Storage\wallet.dat  1
		$a_80_2 = {4f 70 65 6e 56 50 4e 2e 74 78 74 } //OpenVPN.txt  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}