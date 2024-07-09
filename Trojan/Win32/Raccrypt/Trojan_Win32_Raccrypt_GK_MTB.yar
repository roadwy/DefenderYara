
rule Trojan_Win32_Raccrypt_GK_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4e ae 0c 2f c7 45 ?? 61 9b 21 1a c7 45 ?? e7 d0 87 49 c7 45 ?? 96 3a d0 46 c7 45 ?? 29 5f 9d 30 c7 45 ?? 6b 33 00 4b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}