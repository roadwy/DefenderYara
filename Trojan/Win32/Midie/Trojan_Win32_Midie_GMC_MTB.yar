
rule Trojan_Win32_Midie_GMC_MTB{
	meta:
		description = "Trojan:Win32/Midie.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 ?? 53 66 c7 44 24 14 02 00 ff d5 66 89 44 24 12 8b 4f 0c 6a 10 8b 11 8d 4c 24 14 51 8b 02 8b 56 08 52 89 44 24 20 ff 15 } //10
		$a_80_1 = {43 68 37 44 65 6d 6f 36 } //Ch7Demo6  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}