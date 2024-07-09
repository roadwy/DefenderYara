
rule Trojan_Win32_IcedId_SIBJ15_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ15!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 69 00 6e 00 67 00 6c 00 65 00 67 00 6f 00 6f 00 64 00 2e 00 65 00 78 00 65 00 } //1 singlegood.exe
		$a_03_1 = {8b 44 24 10 ?? ?? ?? ?? [0-50] 8b 44 24 10 [0-10] 83 44 24 10 04 81 c7 ?? ?? ?? ?? 89 38 [0-20] ff 4c 24 ?? [0-10] 0f 85 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}