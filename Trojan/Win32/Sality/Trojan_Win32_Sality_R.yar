
rule Trojan_Win32_Sality_R{
	meta:
		description = "Trojan:Win32/Sality.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {6a 6f 68 de 00 00 00 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 83 3d ?? ?? 40 00 00 0f 84 9d 02 00 00 8b 0d ?? ?? 40 00 51 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 8b 15 ?? ?? 40 00 52 6a 00 ff 15 ?? ?? 40 00 } //1
		$a_02_1 = {6a 6f 68 4d 01 00 00 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 83 3d ?? ?? 40 00 00 0f 84 a3 02 00 00 8b 15 ?? ?? 40 00 52 6a 00 ff 15 ?? ?? 40 00 a3 ?? ?? 40 00 a1 ?? ?? 40 00 50 6a 00 ff 15 ?? ?? 40 00 } //1
		$a_00_2 = {5c 25 78 2e 65 78 65 } //1 \%x.exe
		$a_00_3 = {5c 25 64 2e 65 78 65 } //1 \%d.exe
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}