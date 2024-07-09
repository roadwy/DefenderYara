
rule Trojan_Win32_SpyStealer_V_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 66 c7 05 ?? ?? ?? ?? 63 74 c6 05 ?? ?? ?? ?? ?? ff 15 3c 10 40 00 } //10
		$a_02_1 = {50 ff 75 fc ff 35 c4 0a 91 00 ff 35 24 50 ?? ?? ff 15 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}