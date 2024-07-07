
rule Trojan_Win32_Emotetcrypt_VM_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8a 04 90 01 01 30 03 8b 45 90 01 01 8b 5d 90 01 01 3b 75 90 0a 28 00 03 90 02 07 f7 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 90 02 04 f7 f9 90 02 1e 0f b6 90 02 04 a1 90 02 04 8a 0c 90 02 02 8b 44 90 02 02 30 0c 28 90 02 04 45 3b 90 02 04 0f 8c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}