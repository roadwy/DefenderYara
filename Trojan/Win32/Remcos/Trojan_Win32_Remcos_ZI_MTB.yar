
rule Trojan_Win32_Remcos_ZI_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5a 8b ca 99 f7 f9 42 [0-05] 8a 44 50 fe 32 07 88 07 8d 45 f0 8a 17 e8 } //1
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}