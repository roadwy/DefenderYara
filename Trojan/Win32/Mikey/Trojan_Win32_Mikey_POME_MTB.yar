
rule Trojan_Win32_Mikey_POME_MTB{
	meta:
		description = "Trojan:Win32/Mikey.POME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 51 ff 83 e2 ?? 0f b6 92 ?? ?? ?? ?? 89 ce 83 e6 ?? 8a b6 ?? ?? ?? ?? 32 54 0f ff 32 34 0f 88 54 08 ff 88 34 08 83 c1 ?? 81 f9 ?? ?? ?? ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}