
rule Trojan_Win32_NSISInject_RM_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 09 3d 00 6a 54 50 e8 ?? ?? ?? ?? 8b 45 0c 83 c4 0c 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 ff 70 04 ff 15 ?? ?? ?? ?? 8b f0 57 56 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 50 57 89 45 fc ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}