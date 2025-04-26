
rule Trojan_Win32_Enchanim_D{
	meta:
		description = "Trojan:Win32/Enchanim.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 38 06 00 01 40 74 ?? 8b 40 0c 80 38 ec 74 ?? 80 38 e4 74 ?? 80 38 ed 74 ?? b8 00 00 00 00 } //1
		$a_03_1 = {81 38 06 00 01 40 74 ?? 8b 48 0c 80 39 ec 0f 84 ?? ?? ?? ?? 80 39 e4 74 ?? 80 39 ed 0f 84 ?? ?? ?? ?? 80 39 f8 74 ?? 31 c9 } //1
		$a_03_2 = {b2 7a 88 14 ?? c1 ea 08 ?? 78 09 83 ?? 03 75 d2 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*4) >=5
 
}