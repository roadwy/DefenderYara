
rule Trojan_Win32_LummaStealer_STB{
	meta:
		description = "Trojan:Win32/LummaStealer.STB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_01_0 = {b8 fe ff ff ff 90 90 90 90 90 90 90 90 } //1
		$a_01_1 = {b8 ff ff ff ff 90 90 90 90 90 90 90 90 } //1
		$a_03_2 = {0f b6 5d 00 53 e8 ?? ?? ?? ?? 83 c4 04 85 c0 74 ?? 45 90 90 90 90 90 90 90 90 90 90 90 90 } //2
		$a_03_3 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf } //2
		$a_01_4 = {57 58 59 5a 00 78 58 00 } //10 塗婙砀X
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*10) >=15
 
}