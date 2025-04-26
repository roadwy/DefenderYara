
rule Trojan_Win32_Upatre_MH_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 2b d0 89 4d f8 8a 0c 02 88 08 40 ff 4d f8 75 } //5
		$a_01_1 = {68 66 64 66 6a 64 6b 2e 65 78 65 } //5 hfdfjdk.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}