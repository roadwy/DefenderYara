
rule Trojan_Win32_Emotetcrypt_VM_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c2 8a 04 ?? 30 03 8b 45 ?? 8b 5d ?? 3b 75 90 0a 28 00 03 [0-07] f7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 [0-04] f7 f9 [0-1e] 0f b6 [0-04] a1 [0-04] 8a 0c [0-02] 8b 44 [0-02] 30 0c 28 [0-04] 45 3b [0-04] 0f 8c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}