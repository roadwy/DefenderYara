
rule Trojan_Win32_Babar_AYA_MTB{
	meta:
		description = "Trojan:Win32/Babar.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 04 7b 33 d2 6a ?? 59 f7 f1 66 8b 4c 55 ?? 66 89 0c 7b 47 83 ff 08 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}