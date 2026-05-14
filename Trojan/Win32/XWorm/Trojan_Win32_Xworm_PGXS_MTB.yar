
rule Trojan_Win32_Xworm_PGXS_MTB{
	meta:
		description = "Trojan:Win32/Xworm.PGXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 74 70 73 3a 2f 2f 74 72 75 73 74 6e 61 76 69 76 69 65 77 2e 63 6f 6d 2f [0-1f] 2e 62 69 6e } //3
		$a_80_1 = {43 3a 5c 73 79 73 74 65 6d 5c 77 69 6e 64 6f 77 73 20 73 65 72 76 69 63 65 2e 65 78 65 } //C:\system\windows service.exe  2
	condition:
		((#a_03_0  & 1)*3+(#a_80_1  & 1)*2) >=5
 
}