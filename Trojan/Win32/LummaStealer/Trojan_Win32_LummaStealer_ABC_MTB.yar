
rule Trojan_Win32_LummaStealer_ABC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ABC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 f8 89 45 a4 8b 4d c4 0f af 4d 08 89 4d c4 8b 15 ?? ?? ?? ?? 03 55 08 89 15 } //4
		$a_01_1 = {4e 00 44 00 68 00 43 00 35 00 6f 00 37 00 63 00 75 00 35 00 65 00 33 00 30 00 68 00 59 00 65 00 70 00 45 00 47 00 46 00 66 00 } //1 NDhC5o7cu5e30hYepEGFf
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}