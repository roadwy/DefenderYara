
rule Trojan_Win32_Oberal_A_MTB{
	meta:
		description = "Trojan:Win32/Oberal.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {8a 06 46 32 45 f7 50 56 ff 45 f8 8b 75 f8 8a 06 46 8b 5d fc } //2
		$a_80_1 = {66 69 72 65 66 6f 78 65 2e 65 78 65 } //firefoxe.exe  1
		$a_80_2 = {69 65 78 70 6c 6f 72 2e 65 78 65 } //iexplor.exe  1
	condition:
		((#a_00_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}