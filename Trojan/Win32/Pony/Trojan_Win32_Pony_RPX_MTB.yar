
rule Trojan_Win32_Pony_RPX_MTB{
	meta:
		description = "Trojan:Win32/Pony.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 8b 1c 0e e9 95 00 00 00 } //1
		$a_01_1 = {66 09 1c 0f 49 49 85 c9 0f 8d 54 ff ff ff 31 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}