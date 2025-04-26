
rule Trojan_Win32_VBKrypt_AE_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0f 57 c8 81 [0-ff] 39 18 75 [0-ff] ff d0 [0-ff] 8b 1c 17 [0-10] 31 f3 [0-10] 11 1c 10 [0-10] 83 c2 04 [0-10] 81 fa ?? ?? 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}