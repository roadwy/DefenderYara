
rule Trojan_Win32_SpyStealer_VM_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 8d c0 fe ff ff 8b 55 08 83 c2 7c 89 95 38 fd ff ff 8b 45 08 83 c0 0f 89 45 90 8b 4d 08 83 c1 5d 89 8d bc fe ff ff 8b 55 08 } //10
		$a_02_1 = {89 4d e8 8b 95 ?? ?? ?? ?? 0f af 55 e8 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 4d b4 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}