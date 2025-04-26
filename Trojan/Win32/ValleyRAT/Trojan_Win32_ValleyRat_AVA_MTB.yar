
rule Trojan_Win32_ValleyRat_AVA_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.AVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 6a 00 6a 00 68 04 01 00 00 8d 44 24 24 8b f9 50 68 b0 53 40 00 89 7c 24 24 6a 00 89 7c 24 28 ff 15 } //2
		$a_03_1 = {2b 45 e0 6a 40 68 00 30 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}