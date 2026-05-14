
rule Trojan_Win32_Fugrafa_AHB_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 10 01 0f 29 85 ?? ff ff ff 0f 28 85 ?? ff ff ff 66 0f ef 85 ?? ff ff ff 0f 29 85 00 ff ff ff 0f 28 85 00 ff ff ff 8b 55 c8 } //30
		$a_03_1 = {8b 4d 94 83 f0 ?? 83 f1 ?? 89 85 78 ff ff ff 89 8d 7c ff ff ff c7 45 88 ?? 00 00 00 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}