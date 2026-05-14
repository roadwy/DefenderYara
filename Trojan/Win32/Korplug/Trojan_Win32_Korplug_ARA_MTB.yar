
rule Trojan_Win32_Korplug_ARA_MTB{
	meta:
		description = "Trojan:Win32/Korplug.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 ff 74 1c 83 ff fe b8 aa 00 00 00 0f 44 c3 66 33 87 ?? ?? ?? ?? 66 89 44 3c 30 83 c7 02 eb e0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}