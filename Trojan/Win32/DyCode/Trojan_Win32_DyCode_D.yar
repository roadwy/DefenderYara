
rule Trojan_Win32_DyCode_D{
	meta:
		description = "Trojan:Win32/DyCode.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff d0 8b c8 81 e9 ae f6 ff ff 51 } //1
		$a_03_1 = {55 8b ec 83 c4 e8 03 ?? f7 ?? ?? c9 c2 28 00 } //1
		$a_03_2 = {c1 c0 07 03 ?? 41 80 39 00 e9 ?? ?? ?? 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}