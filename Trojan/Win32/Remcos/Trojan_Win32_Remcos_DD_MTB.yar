
rule Trojan_Win32_Remcos_DD_MTB{
	meta:
		description = "Trojan:Win32/Remcos.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 72 65 6d 63 6f 73 5c } //\AppData\Roaming\remcos\  1
		$a_80_1 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 53 63 72 65 65 6e 73 68 6f 74 73 5c } //\AppData\Roaming\Screenshots\  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}