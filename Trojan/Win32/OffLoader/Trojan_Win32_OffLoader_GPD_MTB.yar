
rule Trojan_Win32_OffLoader_GPD_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 68 65 73 73 66 61 6e 67 2e 6f 6e 6c 69 6e 65 2f 70 70 2e 70 68 70 3f 70 65 } //chessfang.online/pp.php?pe  5
		$a_80_1 = {65 64 75 63 61 74 69 6f 6e 63 6f 61 63 68 2e 73 69 74 65 } //educationcoach.site  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}