
rule Trojan_Win32_Razy_NE_MTB{
	meta:
		description = "Trojan:Win32/Razy.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d9 8d 43 ?? 83 38 ?? 75 04 33 c0 eb 34 83 cf ff f0 0f c1 38 4f 75 28 ff 73 ?? 8d 4d ?? e8 cb ad ff ff 8b 03 83 65 fc ?? 8b 70 ?? 8b ce } //3
		$a_01_1 = {4e 00 78 00 54 00 63 00 68 00 2e 00 65 00 78 00 65 00 } //1 NxTch.exe
		$a_01_2 = {69 00 73 00 2e 00 6f 00 6f 00 66 00 66 00 73 00 2e 00 78 00 79 00 7a 00 } //1 is.ooffs.xyz
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}